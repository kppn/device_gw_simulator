require_relative '../util/binary'
require 'json'


class PacketForwarder
  class Head
    include Binary

    bit_structure [
      [24..31, :protocol_version, :numeric],
      [8..23,  :random_token, :numeric],
      [0..7,   :identifier, :enum, {
                              push_data: 0,
                              push_ack:  1,
                              pull_data: 2,
                              pull_ack:  4,
                              pull_resp: 3,
                              tx_ack:    5
                            }],
    ]
    define_option_params_initializer
  end


  attr_accessor :head, :guid, :payload

  def initialize(params = {})
    params.each do |name, value|
      self.send("#{name}=", value)
    end
  end

  def self.from_bytes(byte_str)
    pf = self.new

    pf.head = Head.from_bytes(byte_str[0..3])

    if pf.up?
      pf.guid = byte_str[4..11]
      pf.payload = JSON.parse(byte_str[12..-1]) if pf.payload?
    else
      pf.payload = JSON.parse(byte_str[4..-1]) if pf.payload?
    end

    pf
  end

  def encode
    data = head.encode
    if self.up?
      data += guid
    end
    if self.payload? && self.payload
      data += payload.to_json
    end
    data
  end

  def up?
    case self.head.identifier
    when Head::PushData, Head::PullData, Head::TxAck
      true
    else
      false
    end
  end

  def payload?
    case self.head.identifier
    when Head::PushData, Head::PullResp, Head::TxAck
      true
    else
      false
    end
  end
end

