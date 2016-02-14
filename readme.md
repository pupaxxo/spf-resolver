# SPF IP Address Resolver with PHP

[![Build Status](https://travis-ci.org/rephluX/spf-resolver.svg?branch=master)](https://travis-ci.org/rephluX/spf-resolver)
[![Latest Stable Version](https://poser.pugx.org/rephlux/spf-resolver/v/stable.svg)](https://packagist.org/packages/rephlux/spf-resolver)
[![License](https://poser.pugx.org/rephlux/spf-resolver/license.svg)](https://packagist.org/packages/rephlux/spf-resolver)

## What is SPF

The Sender Policy Framework ([SPF](http://www.openspf.org/Introduction)) is an open standard specifying a technical method to prevent sender address forgery. More precisely, the current version of SPF — called SPFv1 or SPF Classic — protects the envelope sender address, which is used for the delivery of messages.

## Resolve a domain for an existing SPF Record

This package reads and extract all ip addresses from an existing SPF record for a specific domain.

## Installation

Begin by installing this package through Composer.

Run the following command in your terminal to install this package:

```
$ composer require rephlux/spf-resolver
```

Or update your `require` block in your `composer.json` file manually:

```js
{
    "require": {
        ...
        "rephlux/spf-resolver": "0.1.*"
    }
}
```

## Usage

To resolve all ip addresses from a domain, call the appropiate method on the SpfResolver instance and retrieve an array with all ip addresses:

```php
use Rephlux\SpfResolver\SpfResolver;

$spf = new SpfResolver();

$ipAddresses = $spf->resolveDomain('yourdomain.com');

// $ipAddresses = Array(
  [0] => 11.22.33
  [1] => 11.22.34
  [2] => 11.22.35
  [n] => ...
)
```

## Tests

To the run unit tests, simply run the following command in your terminal:

```bash
$ vendor/bin/phpunit
```

## Code Coverage

The unit tests will make code coverage analysis and store the html generated output in the coverage folder.

Code coverage should be at least >90%.
