# NMOS Connection Management API Implementation Changelog

## 2.2.1
- Change variable names, add function for API version and transport type validation, fix tests

## 2.2.0
- Add mechanism to access Sender's receiver_id from driver

## 2.1.5
- Move NMOS packages from recommends to depends

## 2.1.4
- Switch to using facade class from nmosnode

## 2.1.3
- Fix Linting, change tests file structure, add Python 2/3 linting stages to CI

## 2.1.2
- Fix potential race condition in the availability of SDP files

## 2.1.1
- Fix missing files in Python 3 Debian package

## 2.1.0
- Addition of NMOS Oauth2 Security Decorators to protect connection endpoints

## 2.0.2
- Add Python 3 support

## 2.0.1
- Add missing monkey patch call for gevent, potentially causing freezes

## 2.0.0
- Add support for provisional API v1.1

## 1.0.1
- Release version with v1.0 API support
