require 'openssl/cmac'   # https://github.com/hexdigest/openssl-cmac
require_relative '../util/binary'


class LoRaEncryption
  using Binary

  # encrypt payload
  def self.encrypt_payload(data, key, direction, dev_addr, fcnt)
    a = construct_payload_a(direction, dev_addr, fcnt)

    cipher = OpenSSL::Cipher.new("AES-128-CBC").encrypt

    enc_data = data.bound(16).byte_split(16)
                   .map.with_index{|d, i| xor(d, encrypt(cipher, a + (i+1).pack8, key))}
                   .join
    enc_data[0...data.length]
  end

  # encrypt Join Accept
  def self.encrypt_join_accept(data, key)
    cipher = OpenSSL::Cipher.new("AES-128-ECB").decrypt # this is regal (not up side down). see spec
    cipher.padding = 0

    encrypt(cipher, data, key)
  end

  # decrypt Join Accept
  def self.decrypt_join_accept(data, key)
    cipher = OpenSSL::Cipher.new("AES-128-ECB").encrypt # this is regal (not up side down). see spec

    encrypt(cipher, data, key)
  end

  def self.calc_payload_mic(data, key, direction, dev_addr, fcnt)
    a = construct_mic_a(data.bytesize, direction, dev_addr, fcnt)

    OpenSSL::CMAC.digest('AES', key, a+data)[0..3]
  end

  def self.calc_join_mic(data, key)
    OpenSSL::CMAC.digest('AES', key, data)[0..3]
  end

  private 

  def self.encrypt(cipher, data, key)
    cipher.key = key

    data.bound(16).byte_split(16)
        .map{|block| cipher.update(block)}
        .join
  end


  def self.xor(data, other)
    data.each_byte.zip(other.each_byte)
        .map{|a, b| a^b}
        .pack('C*')
  end

  def self.construct_payload_a(direction, dev_addr, fcnt)
    [
      1,                                        # fixed 1
      0, 0, 0, 0,                               # fixed 0, 0, 0, 0
      *[ {up: 0, down: 1}[direction.to_sym] ],  # 0:uplink, 1:downlink
      *dev_addr.unpack('C*'),                   # device address (4 oct little endian)
      *fcnt.pack32.unpack('C*'),                # FCntUp or FCntDown (4 oct little endian)
      0,                                        # fixed 0
      # X                                       # last is 1oct, increment each 16oct block (1..)
    ].pack('C*')
  end

  def self.construct_mic_a(length, direction, dev_addr, fcnt)
    [
      0x49,                                     # fixed 0x49
      0, 0, 0, 0,                               # fixed 0, 0, 0, 0
      *[ {up: 0, down: 1}[direction.to_sym] ],  # 0:uplink, 1:downlink
      *dev_addr.unpack('C*'),                   # device address (4 oct little endian)
      *fcnt.pack32.unpack('C*'),                # FCntUp or FCntDown (4 oct little endian)
      0,                                        # fixed 0
      length                                    # length of msg
    ].pack('C*')
  end
end


