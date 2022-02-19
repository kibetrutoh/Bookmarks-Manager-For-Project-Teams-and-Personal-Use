// logout user

- delete access token from client
- delete user (+ access & refresh tokens) from active token pairs

* get access token
* get user id from token
* get user from token_pair table by user id
* delete the user record from token_pair table
