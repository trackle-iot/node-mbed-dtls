'use strict';

const path = require('path');
const should = require('should');
const sinon = require('sinon');
const assert = require('assert');

const dtls = require('./server');

const opts = {
	cert: path.join(__dirname, 'test/public.der'),
	key: path.join(__dirname, 'test/private.der')
};

describe('server', function() {

});
