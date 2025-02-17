module github.com/umputun/remark42/backend

go 1.15

require (
	github.com/Depado/bfchroma v1.2.0
	github.com/PuerkitoBio/goquery v1.5.1
	github.com/alecthomas/chroma v0.7.2
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/didip/tollbooth/v6 v6.1.0
	github.com/didip/tollbooth_chi v0.0.0-20200828173446-a7173453ea21
	github.com/go-chi/chi/v5 v5.0.2
	github.com/go-chi/cors v1.2.0
	github.com/go-chi/render v1.0.1
	github.com/go-pkgz/auth v1.15.1-0.20210507173239-c99a35bd9b94
	github.com/go-pkgz/jrpc v0.2.0
	github.com/go-pkgz/lcw v0.8.1
	github.com/go-pkgz/lgr v0.10.4
	github.com/go-pkgz/repeater v1.1.3
	github.com/go-pkgz/rest v1.9.2
	github.com/go-pkgz/syncs v1.1.1
	github.com/google/uuid v1.1.2
	github.com/gorilla/feeds v1.1.1
	github.com/hashicorp/go-multierror v1.1.0
	github.com/kyokomi/emoji/v2 v2.2.8
	github.com/microcosm-cc/bluemonday v1.0.9
	github.com/pkg/errors v0.9.1
	github.com/rakyll/statik v0.1.7
	github.com/rs/xid v1.2.1
	github.com/russross/blackfriday/v2 v2.1.0
	github.com/slack-go/slack v0.8.2
	github.com/stretchr/testify v1.7.0
	github.com/umputun/go-flags v1.5.1
	go.etcd.io/bbolt v1.3.5
	go.uber.org/goleak v1.0.0
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
	golang.org/x/image v0.0.0-20210504121937-7319ad40d33e
	golang.org/x/net v0.0.0-20210423184538-5f58ad60dda6
)

replace github.com/go-pkgz/auth => github.com/svkoh/auth v1.5.2
