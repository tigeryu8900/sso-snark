# sso-snark

A proof-of-concept of a single sign-on service based on zk-SNARK.

## Setup

Install package dependencies

```shell
npm install
```

Create a file named `.env` at the project root directory with this content:

```dotenv
MYSQL_HOST=localhost
MYSQL_USERNAME=root
MYSQL_PASSWORD=
SSO_URL=http://localhost:3000
APP_URL=http://localhost:8080
```

You can adjust these values to suit your needs.

## Scripts

These are the npm scripts in this project:

```shell
npm run start:app
npm run start:sso
npm run start
npm run clear:app
npm run clear:sso
npm run clear
```

The first three start the app, sso, and both servers respectively.

The next three clear the app, sso, and both databases respectively.

## SSO server

This is the single sign-on server used to authenticate users for the app server.

The files for the sso server is under the `/sso` directory.

### Register

When someone registers a new user, a nonce is generated, and
`snarkjs.plonk.fullProve` is run in the browser to calculate the output corresponding to the nonce
and password. Then, the username, nonce, and output are sent to the sso server.

The sso server then checks verifies that the username is new and stores the username,
nonce, and output in the database. The user is automatically signed in.

### Sign in

When someone signs in, the browser loads the stored nonce, and
`snarkjs.plonk.fullProve` is run in the browser to calculate a proof using the stored nonce and
entered password.

Then, a new nonce is generated, and `snarkjs.plonk.fullProve` is run with the password and new nonce
to calculate the new output.

Finally, the old proof, new nonce, and new output are sent to the sso server.

The sso server then runs `snarkjs.plonk.verify` to verify that the proof is valid given the old
nonce and stored output. Then, it updates the nonce and output in the database with the new ones.

### Change password

The procedure for changing a password is the same as that for signing in, except that the new output
is calculated using the new password instead.

## App server

This is the app server that calls the sso server to authenticate users.

### Register

When someone registers a new user, they are prompted to enter the URL for the sso server. If both
servers are running locally, that would be `http://localhost:3000`.

Then, the page redirects to the sso server showing the app to be registered. If the user isn't
signed in to the sso server yet, they are prompted to sign in.

After the user clicks `Add App`, the sso server generates a one-time password and a nonce. It then
runs `snarkjs.plonk.fullProve` to calculate the output for the one-time password and nonce. It
stores the one-time password to its database and calls the app server with the username, sso url,
and output, and the app server stores them in its database.

The user is redirected to the app's sign in page.

### Sign in

When someone signs in, they are prompted to enter the URL for the sso server. If both
servers are running locally, that would be `http://localhost:3000`.

Then, the page redirects to the sso server showing the app to be authenticated. If the user isn't
signed in to the sso server yet, they are prompted to sign in.

After the user clicks `Authenticate App`, the sso server first gets the nonce by calling the app
server. Then, it runs `snarkjs.plonk.fullProve` twice: first to calculate the proof for the old
one-time password, and then to calculate the output and proof with newly-generated nonce and one-time
password.

The app server runs `snarkjs.plonk.verify` to verify the old one-time password and stores the new
output and nonce in its database. The sso server stores the new one-time password in its database.

Then, the sso server generates another nonce and runs `snarkjs.plonk.fullProve` again to calculate a
new output and redirects the user to the app server with the proof, new nonce, and new output as
query parameters.

Finally, the app server uses the given query parameters to authenticate the user.

## Security considerations

I considered these vulnerabilities and addressed them in my implementation:

- Since zk-SNARK proofs don't hold information about when it is generated or whether it has been
verified before, so I used a nonce that updates every time someone signs in to prevent replay
attacks.
- Passwords are never sent over the network, so passwords can't be intercepted.
- For the SSO server, a user-dependent catchphrase is displayed upon sign in, so users can tell that
they are signed in to the correct SSO server. Since this is user-dependent, it is hard to create a
fake SSO server.
- The SSO server does not store the proof or the password for signing in to the SSO server. In fact,
all information used to authenticate users to the SSO server can be queried from the server without
signing in. If someone has read access to the database for the SSO server, they still won't be able
to sign in to the SSO server. The credentials for signing in to other apps however, is a different
story.
- The SSO server uses user- and app-dependent one-time passwords that updates every time an app is
authenticated, so if a one-time password is ever leaked, it won't be valid if the user authenticates
an app.
- If the list of one-time passwords ever gets leaked, the SSO server could iterate through them and
regenerate them so that the leaked list of one-time passwords becomes useless. This is not
implemented yet.
