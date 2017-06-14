require_relative '../util/binary'
require 'json'


class PacketForwarder
  class Head
    include Binary

    bit_structure [
      [88..95,   :protocol_version, :numeric],
      [72..87,  :random_token, :numeric],
      [64..71, :identifier, :enum, {
                              push_data: 0,
                              push_ack:  1,
                              pull_data: 2,
                              pull_ack:  3,
                              pull_resp: 4,
                              tx_ack:    5
                            }],
      [0..63, :gateway_unique_identifier, :octets]
    ]
    define_option_params_initializer
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

