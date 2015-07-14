# Signatura

Signatura is an Apache 2.4+ module to do authorization on resources using a signature

# Install

Install CommonCrypto if you're not on Mac OS X or any other OS that doesn't ship with it by default.

Then compile and install the module.

    $ sudo apxs -i -c src/mod_signatura.c
    $ sudo apachectl restart

Now nobody can get into your server without a valid signature.
