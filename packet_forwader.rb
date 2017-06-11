#!/bin/env ruby

require 'pp'
require 'awesome_print'
require 'json'
require 'socket'
require 'base64'

require_relative 'lib/lora/protocol'


def if_hwaddr(if_name)
  sockaddr = Socket.getifaddrs
                  .select{|a| a.name == if_name.to_s}
                  .map(&:addr)
                  .find{|a| a.pfamily == Socket::PF_PACKET}
                  .to_sockaddr
  sockaddr[-6..-1]
end


def generate_eui(if_name)
  hwaddr = if_hwaddr(if_name)
  hwaddr[0..2] + "\xff\xff".force_encoding('ASCII-8BIT') + hwaddr[3..5]
end


def head_basic
  [1, Random.rand(255), Random.rand(255), 0].pack('C4')
end


def head_addr(if_name)
  generate_eui(if_name)
end


def head(kind = :data)
  basic = head_basic
  addr = head_addr('eno1')

  case kind
  when :stat, :data
    basic + addr
  when :pull
    basic[0..2] + [2].pack('C') + addr
  end
end


def stat_msg(rxnb = 0, rxok = 0, rxfw = 0, dwnb = 0, txnb = 0)
  {
    "stat": {
      "time": Time.now.strftime("%F %T %Z"),
      "lati": 35.2442,
      "long": 139.6794,
      "alti": 0,
      "rxnb": rxnb,
      "rxok": rxok,
      "rxfw": rxfw,
      "ackr": 100.0,
      "dwnb": rxnb,
      "txnb": 0,
      #"pfrm": "linux",
      #"mail": "tkondoh58@gmail.com",
      #"desc": "GW stat test",
    }
  }.to_json
end


def data_msg(data, freq)
  {
    "rxpk": [
      {
        "time": Time.now.strftime("%FT%T.%L000Z"),
        "tmst": Time.now.to_i,
        "freq": freq,
        "chan": 2,
        "rfch": 0,
        "stat": 1,
        "modu": "LORA",
        "datr": "SF7BW125",
        #"datr": 12500,
        "codr": "4/5",
        "rssi": -40,
        "lsnr": 2.0,
        "lsnr": 2.0,
        "size": data.length,
        "data": Base64.encode64(data)
        #"data": "QFIWBCYAAAABYeeo6Lm9yLWh"
      }
    ]
  }.to_json
end



#==========================================================-
# main
#==========================================================-
phypayload = PHYPayload.new(
  mhdr: MHDR.new(
    mtype: MHDR::UnconfirmedDataUp
  ),
  macpayload: MACPayload.new(
    fhdr: FHDR.new(
      devaddr: DevAddr.new(
        # 0x26041652
        nwkid:   3,
        nwkaddr: 31992066
      ),
      fctrl: FCtrl.new(
        adr:        false,
        adrackreq:  false,
        ack:        false,
        fpending:   false,
        foptslen:   0
      ),
      fcnt: 1,
      fopts: nil  # "\x02"
    ),
    fport: 0,
    frmpayload: FRMPayload.new("\0x02")
  ),
  mic: '',
  direction: :up
)


joinrequest = PHYPayload.new(
  mhdr: MHDR.new(
    mtype: MHDR::JoinRequest
  ),
  macpayload: JoinRequestPayload.new(
    appeui: ["70b3d57ef0004409"].pack('H*'),
    deveui: ["005d8c57405e7f93"].pack('H*'),
    devnonce: "\x21\x22"
  )
)
# 00 70b3d57ef0004409 005d8c57405e7f93 2122
# 00 70b3d57ef0004409 005d8c57405e7f93 2122 5cd03ec7




appkey  = ["A7CF342AC4C83EE14C73B824E480FC85"].pack('H*')
appskey = ["7BF7C495B7C12A92CB856B35FCD18598"].pack('H*')
nwkskey = ["AF0196F6C67B5B65D20B925BCF010290"].pack('H*')

#host = "bridge.asia-se.thethings.network"   # TTN
host = "150.95.134.143"                     # Conoha


server = UDPSocket.new.tap{|s| s.connect(host, 1700)}


n_rx = 0
n_tx = 0

stat_thread = Thread.new do
  loop do
    stat = head(:stat) + stat_msg(n_rx, n_rx, n_rx)

    server.send stat, 0, nil
    puts 'send stat'
    sleep 100

    n_rx += 1
  end
end

data_thread = Thread.new do
  en_freq = Enumerator.new do |y|
    [
    922.102000,
    922.112000,
    922.122000,
    922.132000,
    922.142000,
    922.152000,
    922.162000,
    ].cycle do |freq|
      y << freq
    end
  end

  begin
    loop do
      phypayload.macpayload.fhdr.fcnt = phypayload.macpayload.fhdr.fcnt + 1
      phypayload.macpayload.frmpayload = FRMPayload.new("hello#{phypayload.macpayload.fhdr.fcnt}")
      lora_data = phypayload.encode(appskey: appskey, nwkskey: nwkskey)
      
      #lora_data = phypayload.encode(nwkskey, nwkskey)
      
      #lora_data = joinrequest.encode(appkey: appkey)

      freq = en_freq.next

      data = head(:data) + data_msg(lora_data, en_freq.next)

      server.send data, 0, nil
      puts "send data. LORA PHYPayload: #{lora_data.to_hexstr}"
      sleep 10
    end
  rescue => e
    p e
    exit
  end
end

pull_thread = Thread.new do
  loop do
    data = head(:pull)

    server.send data, 0, nil
    puts "send pull. PF Head: #{data.to_hexstr}"
    sleep 11
  end
end

stat_thread.join
data_thread.join
pull_thread.join



