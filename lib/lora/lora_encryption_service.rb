require_relative 'lora_encryption'

class LoRaDecryptionService
  def initialize(bytes, keys = {})
    @bytes = bytes
    @appkey  = keys[:appkey]
    @appskey = keys[:appskey]
    @nwkskey = keys[:nwkskey]
  end


  def get_decrypted_phypayload
    phypayload = PHYPayload.new

    phypayload.mhdr       = MHDR.from_bytes(@bytes[0])
    @direction  = phypayload.mhdr.up? ? :up : :down

    phypayload.macpayload, phypayload.mic = 
      case phypayload.mhdr.mtype
      when MHDR::JoinRequest
        calc_decrypted_join_request_and_mic
      when MHDR::JoinAccept
        calc_decrypted_join_accept_and_mic
      else
        calc_decrypted_payload_and_mic
      end

    phypayload.direction = @direction

    phypayload
  end


  private

  def calc_decrypted_join_request_and_mic
    join_request_payload = JoinRequestPayload.from_bytes(@bytes[1..-5])
    mic = @bytes[-4..-1]

    [join_request_payload, mic]
  end


  def calc_decrypted_join_accept_and_mic
    dec_bytes = LoRaEncryption.decrypt_join_accept(@bytes[1..-1], @appkey)

    join_accept_payload = JoinAcceptPayload.from_bytes(dec_bytes[0..-5])
    mic = dec_bytes[-4..-1]

    [join_accept_payload, mic]
  end


  def calc_decrypted_payload_and_mic
    mic = @bytes[-4..-1]
    macpayload = MACPayload.from_bytes(@bytes[1..-5], @direction, encrypted = true)

    return [macpayload, mic] if macpayload.fport == nil

    payload_key = macpayload.fport == 0 ? @nwkskey : @appskey

    decrypted_payload = LoRaEncryption.encrypt_payload(
                          macpayload.frmpayload.encode,
                          payload_key,
                          @direction,
                          macpayload.fhdr.devaddr.encode,
                          macpayload.fhdr.fcnt
                        )
    macpayload.frmpayload = FRMPayload.from_bytes(decrypted_payload, macpayload.fport, @direction)
    
    [macpayload, mic]
  end
end




class LoRaEncryptionService
  def initialize(phypayload, keys = {})
    @phypayload = phypayload
    @appkey  = keys[:appkey]
    @appskey = keys[:appskey]
    @nwkskey = keys[:nwkskey]
  end

  def get_encrypted_payload_and_mic
    case @phypayload.mhdr.mtype
    when MHDR::JoinRequest
      calc_encrypted_join_request_and_mic
    when MHDR::JoinAccept
      calc_encrypted_join_accept_and_mic
    else
      calc_encrypted_payload_and_mic
    end
  end


  private

  # Join Request
  #   data = without encryption
  #   MIC = aes128_cmac(AppKey, MHDR|AppEUI|DevEUI|DevNonce)[0..3]
  def calc_encrypted_join_request_and_mic
    data = [
      @phypayload.mhdr,
      @phypayload.macpayload
    ].map(&:encode).join('')

    mic = LoRaEncryption.calc_join_mic(data, @appkey)

    [data, mic]
  end


  # Join Accept
  #   MIC = aes128_cmac(AppKey, MHDR|AppNonce|NetID|DevAddr|DLSettings|RxDelay|CFList)[0..3]
  #   data = aes128_decrypt(AppKey, AppNonce|NetID|DevAddr|DLSettings|RxDelay|CFList|MIC)
  def calc_encrypted_join_accept_and_mic
    mic_base = [
      @phypayload.mhdr,
      @phypayload.macpayload
    ].map(&:encode).join('')
    mic = LoRaEncryption.calc_join_mic(mic_base, @appkey)

    enc_pay = LoRaEncryption.encrypt_join_accept(@phypayload.macpayload.encode + mic, @appkey)

    data = [@phypayload.mhdr.encode, enc_pay].join('')

    [data[0..-5], data[-4..-1]]
  end


  # DATA Payload
  # enc
  #   Ai = 0x01(1) | 0x00000000(4) | Dir(1) | DevAddr(4) | FCntUp/FCntDown(4) | 0x00(1) | i(1)
  #   S = join( map(1..k)(aes128_encrypt(Key, Ai)) )
  #   data = (pld | pad16) xor S
  # mic
  #   msg = MHDR | FHDR | FPort | FRMPayload
  #   B0 = 0x49(1) | 0x00000000(4) | Dir(1) | DevAddr(4) | FCntUp/FCntDown(4) | 0x00(1) | len(msg)
  #   MIC = aes128_cmac(NwkSKey, B0 | msg)[0..3]
  def calc_encrypted_payload_and_mic
    if @appskey.nil? || @nwkskey.nil?
      raise ArgumentError.new('appskey and nwkskey must be specified')
    end

    payload_key = @phypayload.macpayload.fport == 0 ? @nwkskey : @appskey

    enc_pay = LoRaEncryption.encrypt_payload(
                @phypayload.macpayload.frmpayload.encode,
                payload_key,
                @phypayload.direction,
                @phypayload.macpayload.fhdr.devaddr.encode,
                @phypayload.macpayload.fhdr.fcnt
              )

    data = [
      @phypayload.mhdr.encode,
      @phypayload.macpayload.fhdr.encode,
      @phypayload.macpayload.instance_variable_get("@fport").encode,
      enc_pay
    ].join('')

    mic = LoRaEncryption.calc_payload_mic(
            data,
            @nwkskey,
            @phypayload.direction,
            @phypayload.macpayload.fhdr.devaddr.encode,
            @phypayload.macpayload.fhdr.fcnt
          )

    [data, mic]
  end
end


class KeyGenerator
  def initialize(join_request_phypayload, join_accept_phypayload, appkey)
    @join_request_phypayload = join_request_phypayload
    @join_accept_phypayload = join_accept_phypayload
    @appkey = appkey
  end

  def get_keys
    [get_nwkskey, get_appskey]
  end

  def get_nwkskey
    base = "\x01" + base_common
    LoRaEncryption.encrypt_aes(base, @appkey)
  end

  def get_appskey
    base = "\x02" + base_common
    LoRaEncryption.encrypt_aes(base, @appkey)
  end

  private

  def base_common
    [
      @join_accept_phypayload.macpayload.instance_variable_get('@appnonce').encode +
      @join_accept_phypayload.macpayload.netid.encode +
      @join_request_phypayload.macpayload.instance_variable_get('@devnonce').encode
    ].join
  end
end

