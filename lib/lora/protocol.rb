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
  :appnonce :netid :devaddr :dlsettings :rxdelay :cflist


class PHYPayload
  using LoRaEncrypt
  include Binary

  attr_accessor :mhdr, :macpayload
  attr_accessor :direction

  wrapped_accessor({ mic: [MIC, :value] })
  define_option_params_initializer


  def encode(appskey = nil, nwkskey = nil)
    if mhdr.mtype == MHDR::JoinRequest
      encode_join_request(appskey) # appskey means appkey
    elsif mhdr.mtype == MHDR::JoinAccept
      encode_join_accept(appskey) # appskey means appkey
    elsif appskey
      encode_with_encrypt(appskey, nwkskey)
    else
      encode_without_encrypt
    end
  end

  def encode_join_request(appkey)
    data = [
      mhdr.encode,
      macpayload.encode,
    ].join('')
    mic = data.get_mic(appkey)

    [data, mic].join('')
  end

  def encode_join_accept(appkey)
    mhdr_encoded = mhdr.encode
    enc_base = [
      macpayload.appnonce.encode,
      macpayload.netid.encode,
      macpayload.devaddr.encode,
      macpayload.dlsettings.encode,
      macpayload.rxdelay.encode,
      macpayload.cflist.encode,
    ].join('')

    encrypted = enc_base.encrypt(appkey)
    mic = (mhdr_encoded + encrypted).get_mic(appkay)

    [mhdr_encoded, encrypted, mic].join('')
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

appskey = ["7BF7C495B7C12A92CB856B35FCD18598"].pack('H*')
nwkskey = ["AF0196F6C67B5B65D20B925BCF010290"].pack('H*')

pp phypayload.encode(appskey, nwkskey).to_hexstr

