require_relative '../util/binary'
require_relative 'lora_encryption'
require_relative 'lora_encryption_service'

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
  attr_accessor :value
  
  def initialize(v)
    @value = v
  end
  
  def encode
    value.encode&.force_encoding('ASCII-8BIT')
  end

  def self.from_bytes(byte_str)
    self.new(byte_str)
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
  include Binary
  
  attr_accessor :fhdr, :frmpayload
  wrapped_accessor({ fport: [FPort, :value] })
  define_option_params_initializer
  

  def encode
    frmpayload_enc = frmpayload.encode
    if frmpayload_enc.bytesize == 0
      fport = nil
    end

    [fhdr.encode, @fport.encode, frmpayload_enc].join
  end

  # a_params = direction
  def self.from_bytes(byte_str)
    macpayload = self.new

    macpayload.fhdr       = FHDR.from_bytes(byte_str[0..-1])
    foptslen              = macpayload.fhdr.fctrl.foptslen
    macpayload.fport      = FPort.from_bytes(byte_str[(7+foptslen)..(7+foptslen)])
    macpayload.frmpayload = FRMPayload.from_bytes(byte_str[(8+foptslen)..-1])

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

  def self.from_bytes(byte_str)
    join_request_payload = self.new

    join_request_payload.appeui  = byte_str[0..7]
    join_request_payload.deveui  = byte_str[8..15]
    join_request_payloaddevnonce = byte_str[9..-1]

    join_request_payload
  end
end


class JoinAcceptPayload
  include Binary

  attr_accessor :appnonce, :netid, :devaddr, :dlsettings, :rxdelay, :cflist

  define_option_params_initializer

  def encode
    [appnonce, netid, devaddr, dlsettings, rxdelay, cflist].map(&:encode).join('')
  end

  def self.from_bytes(byte_str)
    join_accept_payload = self.new

    join_accept_payload.appnonce   = byte_str[0..2]
    join_accept_payload.netid      = NetId.from_bytes(byte_str[0..2])
    join_accept_payload.devaddr    = DevAddr.from_bytes(byte_str[3..6])
    join_accept_payload.dlsettings = byte_str[7]
    join_accept_payload.rxdelay    = byte_str[8]
    if byte_str.bytesize >= 9
      join_accept_payload.cflist     = byte_str[9..-1]
    end

    join_accept_payload
  end
end


class PHYPayload
  include Binary

  attr_accessor :mhdr, :macpayload
  attr_accessor :direction

  wrapped_accessor({ mic: [MIC, :value] })
  define_option_params_initializer


  def encode(keys = {})
    if keys.size == 0
      mhdr.encode + macpayload.encode
    else
      service = LoRaEncryptionService.new(self, keys)
      data, @mic = service.get_encrypted_payload_and_mic

      data + @mic
    end
  end


  def self.from_bytes(byte_str, direction = :up, keys)
    service = LoRaDecryptionService.new(byte_str, direction, keys)
    phypayloed = service.get_decrypted_phypayload(bytes, direction, keys)

    phypayloed
  end
end




# ===============================================================--
#  main

appskey = ["01" * 16].pack('H*')
nwkskey = ["01" * 16].pack('H*')


phypayload = PHYPayload.new(
  mhdr: MHDR.new(
    mtype: MHDR::ConfirmedDataUp
  ),
  macpayload: MACPayload.new(
    fhdr: FHDR.new(
      devaddr: DevAddr.new(
        nwkid:   0b1000000,
        nwkaddr: 0b0_10000000_10000000_10001000
      ),
      fctrl: FCtrl.new(
        adr: false,
        adrackreq: false,
	ack: false
      ),
      fcnt: 1,
      fopts: nil
    ),
    fport: 1,
    frmpayload: FRMPayload.new("\x01\x01\x01\x01\x01\x01\x01\x01")
  ),
  mic: '',
  direction: :up
)


p phypayload.encode(appskey: appskey, nwkskey: nwkskey).to_hexstr


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

# pp phypayload.encode(appkey: appskey).to_hexstr


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


#pp phypayload.encode.to_hexstr
#pp phypayload.encode(appkey: appskey).to_hexstr



