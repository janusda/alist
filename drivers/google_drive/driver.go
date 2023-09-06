package google_drive

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/alist-org/alist/v3/drivers/base"
	"github.com/alist-org/alist/v3/internal/conf"
	"github.com/alist-org/alist/v3/internal/driver"
	"github.com/alist-org/alist/v3/internal/errs"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/internal/net"
	"github.com/alist-org/alist/v3/pkg/http_range"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type GoogleDrive struct {
	model.Storage
	Addition
	AccessToken      string
	Client           *resty.Client
	NoRedirectClient *resty.Client
	HttpClient       *http.Client
}

func (d *GoogleDrive) Config() driver.Config {
	return config
}

func (d *GoogleDrive) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *GoogleDrive) Init(ctx context.Context) error {
	if d.ChunkSize == 0 {
		d.ChunkSize = 5
	}
	if d.HttpProxy != "" {
		d.HttpClient = base.NewHttpClient()
		d.Client = base.NewRestyClient()
		d.NoRedirectClient = resty.New().SetRedirectPolicy(
			resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}),
		).SetTLSClientConfig(&tls.Config{InsecureSkipVerify: conf.Conf.TlsInsecureSkipVerify})
		d.NoRedirectClient.SetHeader("user-agent", base.UserAgent)

		proxy, err := url.Parse(d.HttpProxy)
		if err == nil {
			d.HttpClient.Transport = &http.Transport{Proxy: http.ProxyURL(proxy)}
			d.Client.SetProxy(d.HttpProxy)
			d.NoRedirectClient.SetProxy(d.HttpProxy)
		} else {
			log.Errorf("parse http proxy failed: %v", err)
		}
	} else {
		d.HttpClient = base.HttpClient
		d.Client = base.RestyClient
		d.NoRedirectClient = base.NoRedirectClient
	}
	return d.refreshToken()
}

func (d *GoogleDrive) Drop(ctx context.Context) error {
	return nil
}

func (d *GoogleDrive) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	files, err := d.getFiles(dir.GetID())
	if err != nil {
		return nil, err
	}
	return utils.SliceConvert(files, func(src File) (model.Obj, error) {
		return fileToObj(src), nil
	})
}

func (d *GoogleDrive) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	URL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?includeItemsFromAllDrives=true&supportsAllDrives=true", file.GetID())

	var resp File
	_, err := d.request(URL, http.MethodGet, nil, &resp)
	if err != nil {
		log.Errorf("get file info failed: %s, %v", URL, err)
		return nil, err
	}
	curFile := fileToObj(resp)
	size := curFile.GetSize()

	// download
	URL = URL + "&alt=media&acknowledgeAbuse=true"
	resultRangeReader := func(ctx context.Context, r http_range.Range) (io.ReadCloser, error) {
		header := http_range.ApplyRangeToHttpHeader(http_range.Range{Start: r.Start, Length: r.Length}, nil)
		req, err := http.NewRequestWithContext(ctx, "GET", URL, nil)
		if err != nil {
			return nil, err
		}
		header.Set("Authorization", "Bearer "+d.AccessToken)
		req.Header = header

		res, err := d.HttpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if res.StatusCode >= 400 {
			all, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			msg := string(all)
			log.Debugln(msg)
			return nil, fmt.Errorf("http request [%s] failure,status: %d response:%s", URL, res.StatusCode, msg)
		}
		if r.Start == 0 && (r.Length == -1 || r.Length == size) || res.StatusCode == http.StatusPartialContent {
			return res.Body, nil
		} else if res.StatusCode == http.StatusOK {
			log.Warnf("remote http server not supporting range request, expect low perfromace!")
			readCloser, err := net.GetRangedHttpReader(res.Body, r.Start, r.Length)
			if err != nil {
				return nil, err
			}
			return readCloser, nil
		}
		return res.Body, nil
	}

	resultRangeReadCloser := &model.RangeReadCloser{RangeReader: resultRangeReader}
	link := model.Link{
		RangeReadCloser: resultRangeReadCloser,
	}

	return &link, nil
}

func (d *GoogleDrive) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	data := base.Json{
		"name":     dirName,
		"parents":  []string{parentDir.GetID()},
		"mimeType": "application/vnd.google-apps.folder",
	}
	_, err := d.request("https://www.googleapis.com/drive/v3/files", http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
	}, nil)
	return err
}

func (d *GoogleDrive) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	query := map[string]string{
		"addParents":    dstDir.GetID(),
		"removeParents": "root",
	}
	URL := "https://www.googleapis.com/drive/v3/files/" + srcObj.GetID()
	_, err := d.request(URL, http.MethodPatch, func(req *resty.Request) {
		req.SetQueryParams(query)
	}, nil)
	return err
}

func (d *GoogleDrive) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	data := base.Json{
		"name": newName,
	}
	URL := "https://www.googleapis.com/drive/v3/files/" + srcObj.GetID()
	_, err := d.request(URL, http.MethodPatch, func(req *resty.Request) {
		req.SetBody(data)
	}, nil)
	return err
}

func (d *GoogleDrive) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	return errs.NotSupport
}

func (d *GoogleDrive) Remove(ctx context.Context, obj model.Obj) error {
	URL := "https://www.googleapis.com/drive/v3/files/" + obj.GetID()
	_, err := d.request(URL, http.MethodDelete, nil, nil)
	return err
}

func (d *GoogleDrive) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	obj := stream.GetExist()
	var (
		e    Error
		URL  string
		data base.Json
		res  *resty.Response
		err  error
	)
	if obj != nil {
		URL = fmt.Sprintf("https://www.googleapis.com/upload/drive/v3/files/%s?uploadType=resumable&supportsAllDrives=true", obj.GetID())
		data = base.Json{}
	} else {
		data = base.Json{
			"name":    stream.GetName(),
			"parents": []string{dstDir.GetID()},
		}
		URL = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true"
	}
	req := d.NoRedirectClient.R().
		SetHeaders(map[string]string{
			"Authorization":           "Bearer " + d.AccessToken,
			"X-Upload-Content-Type":   stream.GetMimetype(),
			"X-Upload-Content-Length": strconv.FormatInt(stream.GetSize(), 10),
		}).
		SetError(&e).SetBody(data).SetContext(ctx)
	if obj != nil {
		res, err = req.Patch(URL)
	} else {
		res, err = req.Post(URL)
	}
	if err != nil {
		return err
	}
	if e.Error.Code != 0 {
		if e.Error.Code == 401 {
			err = d.refreshToken()
			if err != nil {
				return err
			}
			return d.Put(ctx, dstDir, stream, up)
		}
		return fmt.Errorf("%s: %v", e.Error.Message, e.Error.Errors)
	}
	putUrl := res.Header().Get("location")
	if stream.GetSize() < d.ChunkSize*1024*1024 {
		_, err = d.request(putUrl, http.MethodPut, func(req *resty.Request) {
			req.SetHeader("Content-Length", strconv.FormatInt(stream.GetSize(), 10)).SetBody(stream)
		}, nil)
	} else {
		err = d.chunkUpload(ctx, stream, putUrl)
	}
	return err
}

var _ driver.Driver = (*GoogleDrive)(nil)
