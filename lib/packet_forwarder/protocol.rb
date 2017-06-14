require_relative '../util/binary'
require 'json'


class PacketForwarder
  #PUSH_DATA = 0
 # PUSH_ACK  = 1
 # PULL_DATA = 2
 # PULL_ACK  = 4
 # PULL_RESP = 3
 # TX_ACK    = 5

  class Head
    include Binary
    bit_structure [
      [0..7,   :protocol_version, :numeric],
      [8..23,  :random_token, :numeric],
      [24..31, :identifier, :enum, {
                              push_data: 0,
                              push_ack:  1,
                              pull_data: 2,
                              pull_ack:  3,
                              pull_resp: 4,
                              tx_ack:    5
                            }],
      [32..95, :gateway_unique_identifier, :octets]
    ]
    define_option_params_initializer

    #attr_accessor :protocol_version, :random_token, :identifier, :gateway_unique_identifier

  # def initialize(params = {})
  #   params.each do |name, value|
  #     self.send("#{name}=", value)
  #   end
  # end
#
#    def self.from_bytes(byte_str)
#      head = self.new
#      head.protocol_version = byte_str[0].unpack('C').shift
#      head.random_token = byte_str[1..2].unpack('n').shift
#      head.identifier = byte_str[3].unpack('C').shift
#      head.gateway_unique_identifier = byte_str[41.12]
#      head
#    end
#
#    def encode
#      [
#        [protocol_version, random_token, identifier].pack('CnC'),
#        gateway_unique_identifier
#      ].join
#    end
  end

  attr_accessor :head, :payload

  def initialize(params = {})
    params.each do |name, value|
      self.send("#{name}=", value)
    end
  end

  def self.from_bytes(byte_str)
    pf = self.new
    pf.head = Head.from_bytes(byte_str[0..11])
    pf.payload = JSON.parse(byte_str[12..-1])
    pf
  end

  def encode
    head.encode + payload.to_json
  end
end

pf = PacketForwarder.new(
  head: PacketForwarder::Head.new(
    protocol_version: 1,
    random_token: 65535,
    identifier: PacketForwarder::Head::PullData,
    gateway_unique_identifier: "abcdefgh"
  ),
  payload: {
    rxpk: [
      {
        tmms: 1,
        data: "\x55\x55"
      },
      {
        tmms: 2,
        data: "\x66\x66"
      }
    ]
  }.to_json
)

p pf 
p pf.encode
p pf.encode.to_hexstr
pfnew = PacketForwarder.from_bytes(pf.encode)
p pfnew

