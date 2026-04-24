package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpstreamsDecodesArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/reverse_proxy/upstreams" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Write([]byte(`[{"address":"10.0.0.1:80","num_requests":5,"fails":0},{"address":"10.0.0.2:80","num_requests":0,"fails":3}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	ups, err := c.Upstreams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 {
		t.Fatalf("len=%d", len(ups))
	}
	if ups[0].Address != "10.0.0.1:80" || ups[0].NumRequests != 5 {
		t.Errorf("upstream[0]=%+v", ups[0])
	}
	if ups[1].Fails != 3 {
		t.Errorf("upstream[1].fails=%d", ups[1].Fails)
	}
}

func TestUpstreamsEmptyPoolReturnsEmptySlice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`null`))
	}))
	defer srv.Close()
	ups, err := NewClient(srv.URL).Upstreams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ups == nil {
		t.Error("expected non-nil (empty) slice for null body")
	}
	if len(ups) != 0 {
		t.Errorf("len=%d", len(ups))
	}
}

func TestUpstreamsPropagatesNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL).Upstreams(context.Background()); err == nil {
		t.Fatal("expected error on 500")
	}
}
