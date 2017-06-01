require 'openssl/cmac'   # https://github.com/hexdigest/openssl-cmac
require_relative '../util/binary'


module LoRaEncrypt
  refine String do
    using Binary

    def encrypt(key, kind = :payload)
      ci = case kind
           when :payload
             ci = OpenSSL::Cipher.new("AES-128-CBC")
             ci.encrypt
             ci
           when :join_accept
             ci = OpenSSL::Cipher.new("AES-128-ECB")
             ci.decrypt
             ci.padding = 0
             ci
           end
      ci.key = key

      self.bound(16).scan(/.{16}/)
          .map{|block| ci.update(block)}
          .join
    end

    def encrypt_payload(key, direction, dev_addr, fcnt)
      a = [
        1,                                        # fixed 1
        0, 0, 0, 0,                               # fixed 0, 0, 0, 0
        *[ {up: 0, down: 1}[direction.to_sym] ],  # 0:uplink, 1:downlink
        *dev_addr.unpack('C*'),                   # device address (4 oct little endian)
        *fcnt.pack32.unpack('C*'),                # FCntUp or FCntDown (4 oct little endian)
        0,                                        # fixed 0
        # X                                       # last is 1oct, increment each 16oct block (1..)
      ].pack('C*')

      enc_data = self.bound(16).scan(/.{16}/)
                     .map.with_index{|d, i| d.xor (a + (i+1).pack8).encrypt(key)}
                     .join
      enc_data[0...self.length]
    end


    def encrypt_join_accept(key)
      self.encrypt(key, :join_accept)
    end

    def cmac(key)
      OpenSSL::CMAC.digest('AES', key, self)
    end

    def calc_mic(key, direction, dev_addr, fcnt)
      a = [
        0x49,                                     # fixed 0x49
        0, 0, 0, 0,                               # fixed 0, 0, 0, 0
        *[ {up: 0, down: 1}[direction.to_sym] ],  # 0:uplink, 1:downlink
        *dev_addr.unpack('C*'),                   # device address (4 oct little endian)
        *fcnt.pack32.unpack('C*'),                # FCntUp or FCntDown (4 oct little endian)
        0,                                        # fixed 0
        self.length                               # length of msg
      ].pack('C*')

      (a+self).get_mic(key)
    end

    def get_mic(key)
      self.cmac(key)[0..3]
    end
  end
end

