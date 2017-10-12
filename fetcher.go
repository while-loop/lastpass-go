package lastpass

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	lcrypt "github.com/while-loop/lastpass-go/internal/crypt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"github.com/pkg/errors"
)

type blob struct {
	bytes             []byte
	keyIterationCount int
}

type session struct {
	id                string
	token             string
	keyIterationCount int
	cookieJar         http.CookieJar
	key               []byte
}

func buildLastPassURL(path string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   "lastpass.com",
		Path:   path,
	}
}

var (
	ErrInvalidPassword = fmt.Errorf("invalid username or password")
)

func login(username, password string, twoFa int) (*session, error) {
	iterationCount, err := requestIterationCount(username)
	if err != nil {
		return nil, err
	}
	return make_session(username, password, iterationCount, twoFa)
}

func make_session(username, password string, iterationCount, twoFa int) (*session, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar: cookieJar,
	}

	vals := url.Values{
		"method":     []string{"mobile"},
		"web":        []string{"1"},
		"xml":        []string{"1"},
		"username":   []string{username},
		"hash":       []string{string(makeHash(username, password, iterationCount))},
		"iterations": []string{fmt.Sprint(iterationCount)},
	}
	if twoFa != 0 {
		vals.Set("otp", fmt.Sprintf("%d", twoFa))
	}

	res, err := client.PostForm(buildLastPassURL("login.php").String(), vals)
	if err != nil {
		return nil, errors.Wrap(err, "unable to reach LastPass servers")
	}

	defer res.Body.Close()
	var response struct {
		SessionId string `xml:"sessionid,attr"`
		Token     string `xml:"token,attr"`
	}
	err = xml.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	key := makeKey(username, password, iterationCount)
	return &session{response.SessionId,
		response.Token,
		iterationCount,
		cookieJar,
		key,
	}, nil
}

func fetch(s *session) (*blob, error) {
	u := buildLastPassURL("getaccts.php")
	u.RawQuery = (&url.Values{
		"mobile":    []string{"1"},
		"b64":       []string{"1"},
		"hash":      []string{"0.0"},
		"PHPSESSID": []string{s.id},
	}).Encode()
	client := &http.Client{
		Jar: s.cookieJar,
	}
	res, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusForbidden {
		return nil, ErrInvalidPassword
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}
	b, err = base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	return &blob{b, s.keyIterationCount}, nil
}

func post(postUrl *url.URL, s *session, values *url.Values) (string, error) {
	if values == nil {
		values = &url.Values{}
	}

	values.Set("token", string(s.token))
	client := &http.Client{
		Jar: s.cookieJar,
	}

	res, err := client.PostForm(postUrl.String(), *values)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", res.Status)
	}

	return string(b), nil
}

func encodeValues(values *url.Values) *url.Values {
	newValues := &url.Values{}
	for key, val := range *values {
		for _, v := range val {
			newValues.Add(key, base64.StdEncoding.EncodeToString(s2b(v)))
		}
	}
	return newValues
}

func requestIterationCount(username string) (int, error) {
	res, err := http.DefaultClient.PostForm(
		buildLastPassURL("iterations.php").String(),
		url.Values{
			"email": []string{username},
		})
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}
	count, err := strconv.Atoi(string(b))
	if err != nil {
		return 0, err
	}
	return count, nil
}

func makeKey(username, password string, iterationCount int) []byte {
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), iterationCount, 32, sha256.New)
}

func makeHash(username, password string, iterationCount int) []byte {
	key := makeKey(username, password, iterationCount)
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(string(lcrypt.EncodeHex(key)) + password))
		return lcrypt.EncodeHex(b[:])
	}
	return lcrypt.EncodeHex(pbkdf2.Key([]byte(key), []byte(password), 1, 32, sha256.New))
}
