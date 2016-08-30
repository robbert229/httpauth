
# httpauth
This is an http middleware layer that allows for role based authentication.

## Why?

I come from a mixed background having developed in languages ranging from python to java to .NET to lisp, and I believe that one of the most pleasurable development experiences as far as authentication goes belongs to .NET. I enjoy how simple annotations allow for such a level of control, and are able to do so unintrusively. This library was inspired by it, and the need for an effective and flexible middleware layer that allowed for role based authentication.

##COMING SOON!

###Authorization Cycles
####Succeeds At Authorizing
User attempts to go to authorized page
User is redirected to login page, and authorized page's url is added to the get request as a url parameter
User succeeds in authorization and is redirected to original page

####Fails At Authorizing
User attempts to go to authorized page
User is redirected to login page, and authorized page's url is added to the get request as a url parameter
User fails to authorize, and the authorization page reloads.