require_relative '../util/binary'
require_relative 'encryption'
require 'pp'
require 'awesome_print'

  
class DevAddr
  include Binary
  
  bit_structure [
    :little_endian,
    [31..25, :nwkid,   :numeric],
    [24..0,  :nwkaddr, :numeric],
  ]
  define_option_params_initializer
end


class AppNonce
  include Binary
  
  bit_structure [
    :little_endian,
    [23..0, :value,   :numeric],
  ]
  define_option_params_initializer
end


class NetId
  include Binary
  
  bit_structure [
    :little_endian,
    [23..17, :nwkid,   :numeric],
    [16..0,  :addr,    :numeric],
  ]
  define_option_params_initializer
end
  

class FCtrl
  include Binary
  
  bit_structure [
    [7,    :adr,       :flag],
    [6,    :adrackreq, :flag],
    [5,    :ack,       :flag],
    [4,    :fpending,  :flag],
    [3..0, :foptslen,  :numeric],
  ]
  define_option_params_initializer
end
  
  
class FCnt
  include Binary
  
  bit_structure [
    :little_endian,
    [15..0, :value,   :numeric],
  ]
  define_option_params_initializer
end
  

class FOpts
  include Binary

  attr_accessor :value
  define_option_params_initializer

  def encode
    self || ''
  end

  def self.from_bytes(byte_str)
    self.new.tap{|o| o.value = byte_str.dup}
  end
end
  

class FHDR
  include Binary
  
  attr_accessor :devaddr, :fctrl, :fopts
  wrapped_accessor({
    fcnt:  [FCnt, :value],
    fopts: [FOpts, :value]
  })
  define_option_params_initializer
  
  def encode
    [devaddr, fctrl, @fcnt, fopts].map(&:encode).join
  end

  def self.from_bytes(byte_str)
    fhdr = self.new
    fhdr.devaddr  = DevAddr.from_bytes(byte_str[0..3])
    fhdr.fctrl    = FCtrl.from_bytes(byte_str[4])
    fhdr.fcnt     = FCnt.from_bytes(byte_str[5..6])
    if fhdr.fctrl.foptslen > 0
      fhdr.fopts = FOpts.from_bytes(byte_str[7..(7+fhdr.fctrl.foptslen-1)])
    end
    fhdr
  end
end
  
  
class FPort
  include Binary
  
  bit_structure [
    [7..0, :value,   :numeric],
  ]
  define_option_params_initializer
end
  
  
class FRMPayload
  using LoRaEncrypt

  attr_accessor :value
  
  def initialize(v)
    @value = v
  end
  
  # a_params = direction, devaddr, fcnt
  def encode(key = nil, *a_params)
    encoded_value = value&.force_encoding('ASCII-8BIT')
    if key
      if a_params.length != 3
        raise ArgumentError.new('key specified(encrypt), A parameters must be  direction, devaddr, fcnt')
      end
      encoded_value.encrypt_payload(key, *a_params)
    else
      encoded_value
    end
  end

  # a_params = direction, devaddr, fcnt
  def self.from_bytes(byte_str, key = nil, *a_params)
    if key
      if a_params.length != 3
        raise ArgumentError.new('key specified(encrypt), A parameters must be  direction, devaddr, fcnt')
      end
      self.new(byte_str.encrypt_payload(key, *a_params))
    else
      self.new(byte_str)
    end
  end
end
  
  
class MHDR
  include Binary

  bit_structure [
    [7..5, :mtype, :enum, {
                      join_request:          0,
                      join_accept:           1,
                      unconfirmed_data_up:   2,
                      unconfirmed_data_down: 3,
                      confirmed_data_up:     4,
                      confirmed_data_down:   5,
                      proprietary:           7,
                    }],
    [4..2, :undefined],
    [1..0, :major, :numeric]
  ]
  define_option_params_initializer

  def major
    0
  end
end
 

class MACPayload
  using LoRaEncrypt
  include Binary
  
  attr_accessor :fhdr, :frmpayload
  wrapped_accessor({ fport: [FPort, :value] })
  define_option_params_initializer
  

  # a_params = direction
  def encode(key = nil, *a_params)
    if key && a_params.length != 1
      raise ArgumentError.new('key specified(encrypt), A parameters must be  direction')
    end

    frmpayload_enc = 
      if key
        frmpayload.encode(key, *a_params, fhdr.devaddr.encode, fhdr.fcnt)
      else
        frmpayload.encode
      end

    if frmpayload_enc.bytesize == 0
      fport = nil
    end

    [fhdr.encode, @fport.encode, frmpayload_enc].join
  end

  # a_params = direction
  def self.from_bytes(byte_str, key = nil, *a_params)
    macpayload = self.new

    macpayload.fhdr      = FHDR.from_bytes(byte_str[0..-1])
    foptslen = macpayload.fhdr.fctrl.foptslen
    macpayload.fport = FPort.from_bytes(byte_str[(7+foptslen)..(7+foptslen)])
    payload_bytes = byte_str[(8+foptslen)..-1]
    if key
      macpayload.frmpayload = FRMPayload.from_bytes(
        payload_bytes, key, *a_params, macpayload.fhdr.devaddr.encode, macpayload.fhdr.fcnt
      )
    else
      macpayload.frmpayload = FRMPayload.from_bytes(payload_bytes)
    end

    macpayload
  end
end
  

class MIC
  include Binary

  attr_accessor :value
  define_option_params_initializer

  def encode
    self || ''
  end

  def self.from_bytes(byte_str)
    self.new.tap{|o| o.value = byte_str.dup}
  end
end


class JoinRequestPayload
  include Binary

  attr_accessor :appeui, :deveui, :devnonce

  define_option_params_initializer

  def encode
    [appeui, deveui, devnonce].join('')
  end
end


class JoinAcceptPayload
  include Binary

  attr_accessor :appnonce, :netid, :devaddr, :dlsettings, :rxdelay, :cflist

  define_option_params_initializer

  def encode
    [appnonce, netid, devaddr, dlsettings, rxdelay, cflist].map(&:encode).join('')
  end
end


class PHYPayload
  using LoRaEncrypt
  include Binary

  attr_accessor :mhdr, :macpayload
  attr_accessor :direction

  wrapped_accessor({ mic: [MIC, :value] })
  define_option_params_initializer


  def encode(appskey = nil, nwkskey = nil)
    case mhdr.mtype
    when MHDR::JoinRequest
      # appskey means appkey
      encode_join_request(appskey)
    when MHDR::JoinAccept
      # appskey means appkey
      encode_join_accept(appskey)
    else
      if appskey
        encode_with_encrypt(appskey, nwkskey)
      else
        encode_without_encrypt
      end
    end
  end

  def encode_join_request(appkey)
    data = [
      mhdr.encode,
      macpayload.encode,
    ].join('')

    mic = if appkey
            data.get_mic(appkey)
          else
            ''
          end

    [data, mic].join('')
  end

  def encode_join_accept(appkey)
    mhdr_encoded = mhdr.encode
    payload_encoded = macpayload.encode.force_encoding('ASCII-8BIT')

    if appkey
      mic = (mhdr_encoded + payload_encoded).get_mic(appkey)
      payload_encrypted = (payload_encoded+mic).encrypt_join_accept(appkey)
    else
      mic = nil
      payload_encrypted = payload_encoded
    end

    [mhdr_encoded, payload_encrypted].join('')
  end

  def encode_with_encrypt(appskey, nwkskey)
    macpayload_encoded = macpayload.encode(appskey, direction)
    mic = calc_mic(appskey, nwkskey)
    [mhdr.encode, macpayload_encoded, mic.encode].join('')
  end

  def encode_without_encrypt
    [mhdr.encode, macpayload.encode].join('')
  end

  def calc_mic(appskey, nwkskey)
    # MIC
    #   msg = MHDR | FHDR | FPort | FRMPayload
    #   cmac = aes128_cmac(NwkSKey, B0 | msg)
    #   MIC = cmac[0..3]
    mic_base = [
      mhdr.encode,
      macpayload.fhdr.encode,
      macpayload.instance_variable_get("@fport").encode,
      macpayload.frmpayload.encode(
        appskey,
        direction,
        macpayload.fhdr.devaddr.encode,
        macpayload.fhdr.fcnt
      )
    ].join

    mic_base.calc_mic(nwkskey, direction, macpayload.fhdr.devaddr.encode, macpayload.fhdr.fcnt)
  end

  def calc_mic_join_request(appkey)
    mic_base = [
      mhdr.encode,
      macpayload.frmpayload.encode
    ].join

    mic_base.get_mic(appkey)
  end

  def calc_mic_join_accept(appkey)
    mic_base = [
      mhdr.encode,
      macpayload.frmpayload.encode
    ].join

    mic_base.get_mic(appkey)
  end

  def self.from_bytes(byte_str, key = nil, direction = :up)
    phypayload = self.new

    phypayload.mhdr       = MHDR.from_bytes(byte_str[0])
    if key
      phypayload.macpayload = MACPayload.from_bytes(byte_str[1..-5], key, direction)
    else
      phypayload.macpayload = MACPayload.from_bytes(byte_str[1..-5])
    end
    phypayload.mic        = MIC.from_bytes(byte_str[-4..-1])
    phypayload.direction  = direction

    phypayload
  end
end


phypayload = PHYPayload.new(
  mhdr: MHDR.new(
    mtype: MHDR::JoinRequest
  ),
  macpayload: JoinRequestPayload.new(
    appeui: 'aaaaaaaa',
    deveui: 'bbbbbbbb',
    devnonce: 'aa'
  ),
  mic: '',
  direction: :up
)

phypayload = PHYPayload.new(
  mhdr: MHDR.new(
    mtype: MHDR::JoinAccept
  ),
  macpayload: JoinAcceptPayload.new(
    appnonce: AppNonce.new(value: 0x010203),
    netid:    NetId.new(
                nwkid:   0b0001000,
                addr:    0b0_00010001_00010010
              ),
    devaddr: DevAddr.new(
               nwkid:   0b1000000,
               nwkaddr: 0b0_10000001_10000010_10000011
             ),
    dlsettings: "\x00",
    rxdelay: "\x00",
  ),
  mic: '',
  direction: :up
)

appskey = ["01" * 16].pack('H*')
nwkskey = ["02" * 16].pack('H*')

pp phypayload.encode.to_hexstr
pp phypayload.encode(appskey).to_hexstr

