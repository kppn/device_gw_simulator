require_relative '../util/binary'
require_relative 'lora_encryption'
require_relative 'lora_encryption_service'



#====================================
# Common
#====================================
class ChannelFrequency
  include Binary
  
  bit_structure [
    :little_endian,
    [23..0, :value,   :numeric, factor: 100],    # The actual in Hz is *100
  ]
  define_option_params_initializer
end



#====================================
# MAC Commands
#====================================

class LinkCheckReq
  def encode
    ''
  end

  def self.from_bytes(byte_str)
    self.new
  end
end


class LinkCheckAns
  include Binary
  
  bit_structure [
    [15..8, :margin,   :numeric],
    [ 7..0, :gwcnt,    :numeric]
  ]

  define_option_params_initializer
end



class LinkADRReq
  include Binary
  
  bit_structure [
    [31..28, :datarate,   :enum, {
                            sf12_125khz:  0,
                            sf11_125khz:  1,
                            sf10_125khz:  2,
                            sf9_125khz:   3,
                            sf8_125khz:   4,
                            sf7_125khz:   5,
                            sf7_250khz:   6,
                            fsk_50kbps:   7,
                          }],
    [27..24, :txpower,    :enum, {
                            maxeirp:             0,
                            maxeirp_minus_2db:   1,
                            maxeirp_minus_4db:   2,
                            maxeirp_minus_6db:   3,
                            maxeirp_minus_8db:   4,
                            maxeirp_minus_10db:  5,
                            maxeirp_minus_12db:  6,
                            maxeirp_minus_14db:  7,
                          }],
    [23.. 8, :chmask,     :numeric],
    [ 7,     :undefined],
    [ 6.. 4, :chmaskctl,  :numeric],
    [ 3.. 0, :nbtrans,    :numeric],
  ]
  define_option_params_initializer

  alias old_encode encode
  def encode
    encoded = old_encode
    encoded[0] + encoded[2] + encoded[1] + encoded[3]
  end

  class << self
    alias old_from_bytes from_bytes
    def from_bytes(byte_str)
      byte_str = byte_str[0] + byte_str[2] + byte_str[1] + byte_str[3]
      obj = old_from_bytes(byte_str)
      obj
    end
  end
end


class LinkADRAns
  include Binary
  
  bit_structure [
    [7..3,   :undefined],
    [2..2,   :powerack,       :flag],
    [1..1,   :datarateack,    :flag],
    [0..0,   :channelmaskack, :flag],
  ]
  define_option_params_initializer
end



class DutyCycleReq
  include Binary
  
  bit_structure [
    [7..4,   :undefined],
    [3..0,   :maxdcycle,   :numeric],
  ]
  define_option_params_initializer
end


class DutyCycleAns
  def encode
    ''
  end

  def self.from_bytes(byte_str)
    self.new
  end
end


class RXParamSetupAnsStatus
  include Binary
  
  bit_structure [
    [2..2,   :rx1droffsetack,       :flag],
    [1..1,   :rx2droffsetack,       :flag],
    [0..0,   :channelack,           :flag],
  ]
  define_option_params_initializer
end


class RXParamSetupReq
  include Binary

  attr_accessor :dlsettings
  wrapped_accessor({
    frequency: [ChannelFrequency, :value],
  })
  define_option_params_initializer

  def encode
    [dlsettings, @frequency].map(&:encode).join
  end

  def self.from_bytes(byte_str)
    rxparamsetupreq = self.new
    rxparamsetupreq.dlsettings = DLSettings.from_bytes(byte_str[0])
    rxparamsetupreq.frequency  = ChannelFrequency.from_bytes(byte_str[1..3])
    rxparamsetupreq
  end
end


class RXParamSetupAns
  include Binary

  attr_accessor :status

  define_option_params_initializer

  def encode
    @status.encode
  end

  def self.from_bytes(byte_str)
    rxparamsetupans = self.new
    rxparamsetupans.status = RXParamSetupAnsStatus.from_bytes(byte_str[0])
    rxparamsetupans
  end
end


class DevStatusReq
  attr_accessor :value

  def encode
    ''
  end

  def self.from_bytes(byte_str)
    self.new
  end
end


class DevStatusAns
  include Binary

  #attr_accessor :battery
  bit_structure [
    [15..8,   :battery,       :numeric],
    [ 7..6,   :undefined],
    [ 5..0,   :margin,        :flag],
  ]
  define_option_params_initializer

  attr_accessor :margin

  alias old_encode encode
  def encode
    DevStatusAns.new(
      battery: battery,
      margin: margin & 0x3F
    ).old_encode
  end

  class << self
    alias old_from_bytes from_bytes
    def from_bytes(byte_str)
      devstatusans = old_from_bytes(byte_str[0..1])
      devstatusans.margin -=64 if devstatusans.margin > 31
      devstatusans
    end
  end
end


class DrRange
  include Binary

  bit_structure [
    [ 7..4,   :maxdr,       :numeric],
    [ 3..0,   :mindr,       :numeric],
  ]
  define_option_params_initializer
end


class NewChannelAnsStatus
  include Binary

  bit_structure [
    [ 7..2,   :undefined],
    [ 1..1,   :dataraterangeok,        :flag],
    [ 0..0,   :channelfrequencyok,     :flag],
  ]
  define_option_params_initializer
end


class NewChannelReq
  include Binary

  attr_accessor :chindex, :drrange
  wrapped_accessor({
    frequency: [ChannelFrequency, :value],
  })
  define_option_params_initializer

  def encode
    chindex.pack8 + @frequency.encode + drrange.encode
  end

  def self.from_bytes(byte_str)
    newchannelreq = self.new

    newchannelreq.chindex   = byte_str[0].unpack('C').shift
    newchannelreq.frequency = ChannelFrequency.from_bytes(byte_str[1..3])
    newchannelreq.drrange   = DrRange.from_bytes(byte_str[4..4])

    newchannelreq
  end
end


class NewChannelAns
  include Binary

  attr_accessor :status

  define_option_params_initializer

  def encode
    status.encode
  end

  def self.from_bytes(byte_str)
    newchannelans = self.new

    newchannelans.status = NewChannelAnsStatus.from_bytes(byte_str[0])

    newchannelans
  end
end


class RXTimingSetupReq
  include Binary

  bit_structure [
    [ 7..4,   :undefined],
    [ 3..0,   :del,              :numeric],
  ]
  define_option_params_initializer
end


class RXTimingSetupAns
  attr_accessor :value

  def encode
    ''
  end

  def self.from_bytes(byte_str)
    self.new
  end
end


class EIRPDwellTime
  include Binary

  bit_structure [
    [ 7..6,   :undefined],
    [ 5..5,   :downlinkdwelltime,    :enum, {
                            no_limit:        0,
                            dwelltime_400ms: 1
                          }],
    [ 4..4,   :uplinkdwelltime,  :enum, {
                            no_limit:        0,
                            dwelltime_400ms: 1
                          }],
    [ 3..0,   :maxeirp,   :enum, {
                            maxeirp_8dbm:    0,
                            maxeirp_10dbm:   1,
                            maxeirp_12dbm:   2,
                            maxeirp_13dbm:   3,
                            maxeirp_14dbm:   4,
                            maxeirp_16dbm:   5,
                            maxeirp_18dbm:   6,
                            maxeirp_20dbm:   7,
                            maxeirp_21dbm:   8,
                            maxeirp_24dbm:   9,
                            maxeirp_26dbm:  10,
                            maxeirp_27dbm:  11,
                            maxeirp_29dbm:  12,
                            maxeirp_30dbm:  13,
                            maxeirp_33dbm:  14,
                            maxeirp_36dbm:  15
                          }]
  ]
  define_option_params_initializer
end


class TxParamSetupReq
  include Binary

  attr_accessor :eirpdwelltime

  define_option_params_initializer

  def encode
    eirpdwelltime.encode
  end

  def self.from_bytes(byte_str)
    txparamsetupreq = self.new

    txparamsetupreq.eirpdwelltime = EIRPDwellTime.from_bytes(byte_str[0])

    txparamsetupreq
  end
end


class TxParamSetupAns
  attr_accessor :value

  def encode
    ''
  end

  def self.from_bytes(byte_str)
    self.new
  end
end


class DlChannelAnsStatus
  include Binary

  bit_structure [
    [ 7..2,   :undefined],
    [ 1..1,   :uplinkfrequencyexists,    :flag],
    [ 0..0,   :channelfrequencyok,       :flag],
  ]
  define_option_params_initializer
end


class DlChannelReq
  include Binary

  attr_accessor :chindex
  wrapped_accessor({
    freq: [ChannelFrequency, :value],
  })
  define_option_params_initializer

  def encode
    chindex.pack8 + @freq.encode
  end

  def self.from_bytes(byte_str)
    dlchannelreq = self.new

    dlchannelreq.chindex = byte_str[0].unpack('C').first
    dlchannelreq.freq    = ChannelFrequency.from_bytes(byte_str[1..3])

    dlchannelreq
  end
end


class DlChannelAns
  include Binary

  attr_accessor :status

  define_option_params_initializer

  def encode
    status.encode
  end

  def self.from_bytes(byte_str)
    dlchannelans = self.new

    dlchannelans.status = DlChannelAnsStatus.from_bytes(byte_str[0])

    dlchannelans
  end
end


class MACCommand
  include Binary

  LinkCheck      = 2
  LinkADR        = 3
  DutyCycle      = 4
  RXParamSetup   = 5
  DevStatus      = 6
  NewChannel     = 7
  RXTimingSetup  = 8
  TxParamSetup   = 9
  DlChannel      = 10

  MACCommandKlasses = {
     2 => {up:   LinkCheckReq,     down: LinkCheckAns},
     3 => {down: LinkADRReq,       up:   LinkADRAns},
     4 => {down: DutyCycleReq,     up:   DutyCycleAns},
     5 => {down: RXParamSetupReq,  up:   RXParamSetupAns},
     6 => {down: DevStatusReq,     up:   DevStatusAns},
     7 => {down: NewChannelReq,    up:   NewChannelAns},
     8 => {down: RXTimingSetupReq, up:   RXTimingSetupAns},
     9 => {down: TxParamSetupReq,  up:   TxParamSetupAns},
    10 => {down: DlChannelReq,     up:   DlChannelAns},
  }

  attr_accessor :cid, :payload

  define_option_params_initializer

  def encode
    cid.pack8 + payload.encode
  end

  def self.from_bytes(byte_str, direction = :up)
    cmd = self.new
    cmd.cid = byte_str[0].unpack('C').shift

    klass = MACCommandKlasses[cmd.cid][direction]
    cmd.payload = klass.from_bytes(byte_str[1..-1])

    cmd
  end
end


#====================================
# LoRa Basics
#====================================

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
    [23..0, :value,   :octets],
  ]
  define_option_params_initializer
end


class DevNonce
  include Binary
  
  bit_structure [
    :little_endian,
    [15..0, :value,   :octets],
  ]
  define_option_params_initializer
end


class NetId
  include Binary
  
  bit_structure [
    :little_endian,
    [23..7,  :addr,    :numeric],
    [ 6..0,  :nwkid,   :numeric],
  ]
  define_option_params_initializer
end


class DLSettings
  include Binary
  
  bit_structure [
    [7,     :undefined],
    [6..4,  :rx1droffset,   :numeric],
    [3..0,  :rx2datarate,   :numeric],
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
    self.value.encode
  end

  def self.from_bytes(byte_str, direction = :up)
    fopts = self.new
    fopts.value = MACCommand.from_bytes(byte_str, direction)
    fopts
  end
end
  

class FHDR
  include Binary
  
  attr_accessor :devaddr, :fctrl
  wrapped_accessor({
    fcnt:     [FCnt, :value],
    fopts:    [FOpts, :value]
  })
  define_option_params_initializer
  
  def encode
    [devaddr, fctrl, @fcnt, @fopts].map(&:encode).join
  end

  def self.from_bytes(byte_str, direction = :up)
    fhdr = self.new
    fhdr.devaddr  = DevAddr.from_bytes(byte_str[0..3])
    fhdr.fctrl    = FCtrl.from_bytes(byte_str[4])
    fhdr.fcnt     = FCnt.from_bytes(byte_str[5..6])
    if fhdr.fctrl.foptslen > 0
      fhdr.fopts = FOpts.from_bytes(byte_str[7..(7+fhdr.fctrl.foptslen-1)], direction)
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

  def up?
    case mtype
    when MHDR::JoinRequest, MHDR::UnconfirmedDataUp, MHDR::ConfirmedDataUp
      true
    else
      false
    end
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

  def self.from_bytes(byte_str, direction = :up)
    macpayload = self.new

    macpayload.fhdr       = FHDR.from_bytes(byte_str[0..-1], direction)
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
    value || ''
  end

  def self.from_bytes(byte_str)
    self.new.tap{|o| o.value = byte_str.dup}
  end
end


class EUI
  include Binary

  bit_structure [
    :little_endian,
    [63..0, :value, :octets]
  ]
  define_option_params_initializer
end


class AppEUI < EUI
end


class DevEUI < EUI
end


class JoinRequestPayload
  include Binary

  wrapped_accessor({
    appeui: [AppEUI, :value],
    deveui: [DevEUI, :value],
    devnonce: [DevNonce, :value]
  })
  define_option_params_initializer

  def encode
    [@appeui, @deveui, @devnonce].map(&:encode).join('')
  end

  def self.from_bytes(byte_str)
    join_request_payload = self.new

    join_request_payload.appeui   = AppEUI.from_bytes(byte_str[0..7])
    join_request_payload.deveui   = DevEUI.from_bytes(byte_str[8..15])
    join_request_payload.devnonce = DevNonce.from_bytes(byte_str[16..-1])

    join_request_payload
  end
end


class CFList
  include Binary

  wrapped_accessor({
    ch3: [ChannelFrequency, :value],
    ch4: [ChannelFrequency, :value],
    ch5: [ChannelFrequency, :value],
    ch6: [ChannelFrequency, :value],
    ch7: [ChannelFrequency, :value],
  })
  define_option_params_initializer

  def encode
    [@ch3, @ch4, @ch5, @ch6, @ch7].map(&:encode).join + "\x0" # 1Byte zero as RFU
  end

  def self.from_bytes(byte_str)
    cflist = self.new
    cflist.ch3 = ChannelFrequency.from_bytes(byte_str[0..2])
    cflist.ch4 = ChannelFrequency.from_bytes(byte_str[3..5])
    cflist.ch5 = ChannelFrequency.from_bytes(byte_str[6..8])
    cflist.ch6 = ChannelFrequency.from_bytes(byte_str[9..11])
    cflist.ch7 = ChannelFrequency.from_bytes(byte_str[12..14])
    cflist
  end
end


class Delay
  include Binary

  bit_structure [
    [7..4, :undefined],
    [3..0, :value,   :numeric]
  ]
  define_option_params_initializer
end


class RXDelay < Delay
end


class JoinAcceptPayload
  include Binary

  attr_accessor :netid, :devaddr, :dlsettings, :cflist
  wrapped_accessor({
    appnonce: [AppNonce, :value],
    rxdelay:  [Delay, :value]
  })
  define_option_params_initializer

  def encode
    [@appnonce, netid, devaddr, dlsettings, @rxdelay, cflist].map(&:encode).join('')
  end

  def self.from_bytes(byte_str)
    join_accept_payload = self.new

    join_accept_payload.appnonce   = AppNonce.from_bytes(byte_str[0..2])
    join_accept_payload.netid      = NetId.from_bytes(byte_str[3..5])
    join_accept_payload.devaddr    = DevAddr.from_bytes(byte_str[6..9])
    join_accept_payload.dlsettings = DLSettings.from_bytes(byte_str[10])
    join_accept_payload.rxdelay    = RXDelay.from_bytes(byte_str[11])
    if byte_str.bytesize > 12
      join_accept_payload.cflist     = CFList.from_bytes(byte_str[12..27])
    end

    join_accept_payload
  end
end


class PHYPayload
  include Binary

  attr_accessor :raw, :raw_encrypted
  attr_accessor :mhdr, :macpayload
  attr_accessor :direction

  wrapped_accessor({ mic: [MIC, :value] })
  define_option_params_initializer with: ->{ set_direction }


  def encode(keys = {})
    set_direction unless direction

    if keys.size == 0
      self.raw = mhdr.encode + macpayload.encode
    else
      service = LoRaEncryptionService.new(self, keys)
      data, @mic = service.get_encrypted_payload_and_mic
      selfraw_encrypted = data + @mic
    end
  end


  def self.from_bytes(byte_str, keys = {})
    if keys.size == 0
      phypayload = self.new
      phypayload.mhdr = MHDR.from_bytes(byte_str[0])
      phypayload.set_direction

      phypayload.macpayload = case phypayload.mhdr.mtype
                              when MHDR::JoinRequest
                                JoinRequestPayload.from_bytes(byte_str[1..-1])
                              when MHDR::JoinAccept
                                JoinAcceptPayload.from_bytes(byte_str[1..-1])
                              else
                                MACPayload.from_bytes(byte_str[1..-1], phypayload.direction)
                             end

      phypayload.raw = byte_str
      phypayload
    else
      service = LoRaDecryptionService.new(byte_str, keys)
      phypayload = service.get_decrypted_phypayload
      phypayload.raw = phypayload.encode
      phypayload.raw_encrypted = byte_str
      phypayload
    end
  end


  def set_direction
    self.direction = mhdr&.up? ? :up : :down
  end
end

