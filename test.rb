require 'test/unit'
require 'time'
require 'rcsfile'

class BasicsTest < Test::Unit::TestCase
  def setup
    @f = RCSFile.new('test,v')
  end

  def test_file
    assert(@f.head == '1.472', 'Correct HEAD')
  end

  def test_symbols
    s = @f.symbols
    assert(s['RELENG_4'] == '1.141.0.2', 'Symbol lookup')
  end

  def test_locks
    assert(@f.locks == {}, 'Locks')
  end

  def test_resolve_sym
    assert(@f.resolve_sym('RELENG_4') == '1.141.2.70', 'Resolve sym')
  end

  def test_revs
    assert(@f.key?('1.1'), 'Rev lookup')
    assert(!@f.key?('1.500'), 'Rev lookup 2')
    assert(@f['1.1'] != nil, 'Rev lookup 3')
    assert(@f['1.120'].date == Time.parse('Thu Dec 30 11:31:21 CET 1999'),
	'Positive rev time (2-digit year)')
    assert(@f['1.121'].date == Time.parse('Tue Jan 04 15:12:12 CET 2000'),
	'Rev time (4-digit year)')
  end

  def test_close
    @f.close
    begin
      @f.head
      assert(false, "Read file after close")
    rescue IOError
      assert(true)
    end
    # restore for teardown
    @f = RCSFile.new('test,v')
  end

  def test_open
    RCSFile.open('test,v') do |f|
      assert(f.head == '1.472', 'open with block')
    end

    f = RCSFile.open('test,v')
    assert(f.head == '1.472', 'open without block')
    f.close
  end

  def teardown
    @f.close
  end
end
