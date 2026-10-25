package adapters

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pep691 = "application/vnd.pypi.simple.v1+json"

func TestIsIndexRequest(t *testing.T) {
	a := NewPyPIAdapter([]string{"https://pypi.org"})
	for path, want := range map[string]bool{
		"/simple/":               true,
		"/simple/torch/":         true,
		"/pypi/torch/json":       true,
		"/pypi/torch/2.5.1/json": true,
		"/packages/ab/x.whl":     false,
		"/pypi/torch":            false,
	} {
		assert.Equal(t, want, a.IsIndexRequest(httptest.NewRequest("GET", path, nil)), path)
	}
}

func rewrite(t *testing.T, doc, contentType, path string) (string, []string, int) {
	t.Helper()
	res, err := NewPyPIAdapter([]string{"https://pypi.org"}).RewriteIndex([]byte(doc), contentType, path)
	require.NoError(t, err)
	return string(res.Body), res.Dropped, res.Rewritten
}

func TestRewriteIndex_HTMLRewritesAbsolutePackageLinks(t *testing.T) {
	doc := `<a href="https://files.pythonhosted.org/packages/8b/5c/x-1.0-py3-none-any.whl#sha256=ab" data-requires-python="&gt;=3.8">x-1.0-py3-none-any.whl</a><br />`
	body, dropped, n := rewrite(t, doc, "text/html", "/simple/x/")
	assert.Equal(t, `<a href="../../packages/8b/5c/x-1.0-py3-none-any.whl#sha256=ab" data-requires-python="&gt;=3.8">x-1.0-py3-none-any.whl</a><br />`, body)
	assert.Empty(t, dropped)
	assert.Equal(t, 1, n)
}

func TestRewriteIndex_HTMLKeepsRelativeLinks(t *testing.T) {
	doc := `<a href="../../packages/a/b-1.0.tar.gz#sha256=cd">b-1.0.tar.gz</a>`
	body, dropped, n := rewrite(t, doc, "text/html", "/simple/b/")
	assert.Equal(t, doc, body)
	assert.Empty(t, dropped)
	assert.Zero(t, n)
}

func TestRewriteIndex_HTMLDropsForeignAbsolute(t *testing.T) {
	doc := "<a href=\"https://files.pythonhosted.org/packages/a/x-1.0.tar.gz\">ok</a>\n" +
		"<a href='https://evil.example/x-1.0.tar.gz'>bad</a>\n"
	body, dropped, n := rewrite(t, doc, "text/html", "/simple/x/")
	assert.NotContains(t, body, "evil.example")
	assert.Contains(t, body, `href="../../packages/a/x-1.0.tar.gz"`)
	assert.Equal(t, []string{"https://evil.example/x-1.0.tar.gz"}, dropped)
	assert.Equal(t, 1, n)
}

func TestRewriteIndex_HTMLRemovesBase(t *testing.T) {
	doc := `<html><head><base href="https://files.pythonhosted.org/"></head><body></body></html>`
	body, _, _ := rewrite(t, doc, "text/html", "/simple/x/")
	assert.NotContains(t, strings.ToLower(body), "<base")
}

func TestRewriteIndex_DepthFollowsRequestPath(t *testing.T) {
	doc := `<a href="https://files.pythonhosted.org/packages/a/x.whl">x</a>`
	body, _, _ := rewrite(t, doc, "text/html", "/simple/x")
	assert.Contains(t, body, `href="../packages/a/x.whl"`)
}

func TestRewriteIndex_JSONSimple(t *testing.T) {
	doc := `{"meta":{"api-version":"1.1"},"name":"x","versions":["1.0"],"files":[
		{"filename":"x-1.0.whl","url":"https://files.pythonhosted.org/packages/a/x-1.0.whl#sha256=ab","hashes":{"sha256":"ab"}},
		{"filename":"x-1.0.tar.gz","url":"https://evil.example/x-1.0.tar.gz","hashes":{}}]}`
	body, dropped, n := rewrite(t, doc, pep691, "/simple/x/")

	var got struct {
		Meta     map[string]string `json:"meta"`
		Name     string            `json:"name"`
		Versions []string          `json:"versions"`
		Files    []struct {
			Filename string            `json:"filename"`
			URL      string            `json:"url"`
			Hashes   map[string]string `json:"hashes"`
		} `json:"files"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Equal(t, "1.1", got.Meta["api-version"])
	assert.Equal(t, "x", got.Name)
	assert.Equal(t, []string{"1.0"}, got.Versions)
	require.Len(t, got.Files, 1)
	assert.Equal(t, "../../packages/a/x-1.0.whl#sha256=ab", got.Files[0].URL)
	assert.Equal(t, "ab", got.Files[0].Hashes["sha256"])
	assert.Equal(t, []string{"https://evil.example/x-1.0.tar.gz"}, dropped)
	assert.Equal(t, 1, n)
}

func TestRewriteIndex_JSONAPI(t *testing.T) {
	doc := `{"info":{"name":"x"},"urls":[{"url":"https://files.pythonhosted.org/packages/a/x-1.0.whl"}],
		"releases":{"1.0":[{"url":"https://files.pythonhosted.org/packages/a/x-1.0.whl"}]}}`

	for path, prefix := range map[string]string{
		"/pypi/x/json":     "../../packages/",
		"/pypi/x/1.0/json": "../../../packages/",
	} {
		body, dropped, n := rewrite(t, doc, "application/json", path)
		var got struct {
			Info     map[string]string                 `json:"info"`
			URLs     []struct{ URL string }            `json:"urls"`
			Releases map[string][]struct{ URL string } `json:"releases"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &got), path)
		assert.Equal(t, "x", got.Info["name"], path)
		assert.Equal(t, prefix+"a/x-1.0.whl", got.URLs[0].URL, path)
		assert.Equal(t, prefix+"a/x-1.0.whl", got.Releases["1.0"][0].URL, path)
		assert.Empty(t, dropped, path)
		assert.Equal(t, 2, n, path)
	}
}

func TestRewriteIndex_MalformedJSONErrors(t *testing.T) {
	_, err := NewPyPIAdapter([]string{"https://pypi.org"}).RewriteIndex([]byte("{"), pep691, "/simple/x/")
	assert.Error(t, err)
}
