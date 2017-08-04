#!/bin/env ruby

require 'pp'
require 'json'
require 'base64'
require 'rubygems'
require 'pcaprub'
require_relative 'lib/lora/protocol'


lora_bytes = "@\x94\x1E\x04&\x80\xD3\x03\x01\x15x\x86\x8B#b\x8E\x03"

appkey  = ["FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"].pack('H*')
appskey = ["74ADCDC988A9B513F2A03FB9C39CE781"].pack('H*')
nwkskey = ["47E3C9151666263D07C34311696FE772"].pack('H*')

pp PHYPayload.from_bytes(lora_bytes, appkey: appkey, nwkskey: nwkskey, appskey: appskey)



