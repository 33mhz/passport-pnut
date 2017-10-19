# Passport-Pnut

[Passport](https://github.com/jaredhanson/passport) strategy for authenticating
with [pnut.io](https://pnut.io) using the OAuth 2.0 API.

## Installation

    $ npm install passport-pnut

## Usage

#### Configure Strategy

The pnut.io authentication strategy authenticates users using a pnut.io account and
OAuth tokens.  The strategy requires a `verify` callback, which accepts these
credentials and calls `done` providing a user, as well as `options` specifying a
consumer key, consumer secret, and callback URL.

    const PnutStrategy = require("passport-pnut").Strategy;

    passport.use(new PnutStrategy({
        clientID: PNUT_CLIENT_ID,
        clientSecret: PNUT_CLIENT_SECRET,
        callbackURL: "http://127.0.0.1:3000/auth/pnut/callback"
      },
      function(token, tokenSecret, profile, done) {
        User.findOrCreate({ pnutId: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'pnut'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/pnut',
      passport.authenticate('pnut'),
      function(req, res){
        // The request will be redirected to pnut.io for authentication, so this
        // function will not be called.
      });

    app.get('/auth/pnut/callback',
      passport.authenticate('pnut', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Credits
  - [Michael Owens](https://github.com/mowens)
  - [Jen Fong-Adwent](https://github.com/ednapiranha)

## Thanks
  - [Jared Hanson](https://github.com/jaredhanson)
  - [Dalton Caldwell](https://github.com/daltonc)
  - [The App.net Team](https://github.com/appdotnet)

## License

(The MIT License)

Copyright (c) 2012 Michael Owens

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
