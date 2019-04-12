#!/usr/bin/env ruby

require 'bundler/setup'
require 'sinatra'
require 'openssl'
require 'json'
require 'net/http'
require 'uri'
require 'jwt'

set :bind, '0.0.0.0'

State = {}

def private_key
  State[:private_key] ||= OpenSSL::PKey::RSA.generate(2048)
end

def create_jwks
  public_key = private_key.public_key

  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 0
  cert.not_before = Time.now
  cert.not_after = Time.now + 3600
  cert.public_key = public_key
  cert.sign(private_key, OpenSSL::Digest::SHA1.new)
  x5c = cert.to_s.lines[1..-2].join.gsub("\n", '')

  key = {
    x5c: [
      x5c
    ],
    kid: 'mock_key'
  }

  uri = URI.parse("https://auth.mozilla.auth0.com/.well-known/jwks.json")
  request = Net::HTTP::Get.new(uri.request_uri, headers)
  response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
    http.request(request)
  end
  body = JSON.parse(response.body)

  {
    keys: body["keys"].push(key)
  }.to_json
end

def jwks
  State[:jwks] ||= create_jwks
end

def create_jwt(payload)
  JWT.encode(payload, private_key, 'RS256', {
    kid: 'mock_key'
  })
end

get '/.well-known/jwks.json' do
  content_type :json
  jwks
end

post '/' do
  content_type :json
  data = JSON.parse(request.body.read.to_s)

  uri = URI.parse(data["url"])
  jwt = create_jwt(data["payload"].merge({
    exp: Time.now.to_i + 604800,
    iat: Time.now.to_i
  }))

  headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer #{jwt}"
  }

  http = Net::HTTP.new(uri.host, uri.port)
  request = Net::HTTP::Post.new(uri.request_uri, headers)
  request.body = data["body"].to_json

  response = http.request(request)

  {
    request: {
      headers: headers,
      body: data["body"]
    },
    response: {
      status: response.code,
      body: response.body
    }
  }.to_json
end
