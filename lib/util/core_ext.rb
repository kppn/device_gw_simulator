class NilClass
  def encode(*dummy)
    ''.force_encoding('ASCII-8BIT')
  end
end


class TrueClass
  def to_i
    1
  end
end


class FalseClass
  def to_i
    0
  end
end


class Integer
  def pack8
    [self].pack('C')
  end

  def pack16
    [self].pack('S')
  end

  def pack32
    [self].pack('L')
  end

  def to_boolean
    if self == 0
      false
    elsif self == 1
      true
    else
      nil
    end
  end
end


class Fixnum
  def bits(pos, value)
    case pos
    when Integer
      set_bit(self, pos, value)
    when Range
      f = pos.first
      l = pos.exclude_end? ? pos.last - 1 : pos.last
      x = self
      (f..l).each do |p|
        x = set_bit(x, p, value&1)
        value >>= 1
      end
      x
    end
  end

  alias old_blace :'[]'
  def [](pos)
    case pos
    when Integer
      self.old_blace(pos)
    when Range
      f = pos.first
      l = pos.exclude_end? ? pos.last - 1 : pos.last
      mask = (1 << (l-f+1)) -1
      (self >> f) & mask
    end
  end

  private

  def set_bit(v, pos, value)
    v &= ~(1<<pos)
    v |= ((value&1)<<pos)
  end
end


class String
  def to_hexstr
    self.each_byte.map{|x| "%02x" % x}.join
  end

  def bound(len, pad = "\x0")
    next_bound = (self.length + (len-1)) / len  * len
    self + (pad * (next_bound - self.length))
  end
end

