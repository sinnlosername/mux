package mux

import (
	"net/http"
	"net"
	"io/ioutil"
	"net/url"
	"log"
	"encoding/json"
	"time"
)

type RLMap map[time.Duration]int

const recaptchaUrl = "https://www.google.com/recaptcha/api/siteverify"

var RateLimitCaptchaSecret string

func ratelimitBlockIp(r *Router, remoteAddr net.IP) (handler http.Handler) {
	r.blockedIps = append(r.blockedIps, remoteAddr)
	return ratelimitHandle(r)
}

func ratelimitHandle(r *Router) (handler http.Handler) {
	if handler = r.RateLimitHandler; handler == nil {
		handler = rateLimitHandler()
	}
	return
}

func ratelimitIsBlocked(match RouteMatch, r *Router, remoteAddr net.IP, req *http.Request) (isBlocked, unblocked bool) {
	if !r.IsIpBlocked(remoteAddr) {
		return false, false
	}

	if req.RequestURI == "/unblock-ratelimit" && ratelimitUnblock(req) {
		ratelimitRemoveIp(r, remoteAddr)
		if match.Route != nil {
			ratelimitRemoveAccesses(match.Route, remoteAddr)
		}
		return false, true
	}

	return true, false
}

func ratelimitRemoveAccesses(route *Route, ip net.IP) {
	for k, v := range route.accesses{
		if !v.Equal(ip) {
			continue
		}
		delete(route.accesses, k)
	}
}

func ratelimitRemoveIp(r *Router, ip net.IP) {
	for i, v := range r.blockedIps {
		if !v.Equal(ip) {
			continue
		}

		//Removing array elements in go is so fancy
		r.blockedIps[len(r.blockedIps)-1], r.blockedIps[i] = r.blockedIps[i], r.blockedIps[len(r.blockedIps)-1]
		r.blockedIps = r.blockedIps[:len(r.blockedIps)-1]
	}
}

func ratelimitUnblock(req *http.Request) bool {
	if req.Method != "POST" {
		return false
	}
	defer req.Body.Close()

	var token string

	if data, err := ioutil.ReadAll(req.Body); err == nil {
		if len(data) < 5 || len(data) > 1024*16 {
			return false
		}

		token = string(data)
	} else {
		return false
	}

	return ratelimitRecaptchaCheck(token, req.RemoteAddr)
}

func ratelimitRecaptchaCheck(captcha, ip string) (bool) {
	resp, err := http.PostForm(recaptchaUrl, url.Values{"secret": {RateLimitCaptchaSecret}, "remoteip": {ip}, "response": {captcha}})

	if err != nil {
		log.Println("Unable to verify google recaptcha")
		log.Println(err)
		return false
	}

	var response map[string]interface{}

	if jsondata, err := ioutil.ReadAll(resp.Body); err != nil {
		log.Println("Unable to read recaptcha response")
		log.Println(err)
		return false
	} else {
		json.Unmarshal(jsondata, &response)
	}

	return response["success"].(bool)
}

func rateLimitHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("429 - Too many requests - Sadly, thhe creator didn't put a captcha here :("))
	})
}
