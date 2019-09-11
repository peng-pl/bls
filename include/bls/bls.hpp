#pragma once
/**
	@file
	@brief BLS threshold signature on BN curve
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/

#define MCLBN_FP_UNIT_SIZE 4

#include <array>
#include <mcl/bn.h>
#include <mcl/op.hpp>
#include <bls/bls.h>
#include <vector>
#include <string>
#include <iosfwd>
#include <stdint.h>
#include <iostream>
using namespace std;
#include <string.h>

#ifdef _MSC_VER
	#pragma comment(lib, "bls.lib")
#endif


#define HASH_2nd_128BIT


namespace bls {

// same value with IoMode of mcl/op.hpp
enum {
	IoBin = 2, // binary number
	IoDec = 10, // decimal number
	IoHex = 16, // hexadecimal number
	IoFixedByteSeq = 512 // fixed byte representation
};

typedef cybozu::Exception Exception;

namespace impl {

struct SecretKey;
struct PublicKey;
struct Signature;
struct Id;

} // bls::impl

/*
	BLS signature
	e : G2 x G1 -> Fp12
	Q in G2 ; fixed global parameter
	H : {str} -> G1
	s : secret key
	sQ ; public key
	s H(m) ; signature of m
	verify ; e(sQ, H(m)) = e(Q, s H(m))
*/

/*
	initialize this library
	call this once before using the other method
	@param curve [in] type of curve
	@param maxUnitSize [in] 4 or 6 (specify same value used in compiling for validation)
	@note init() is not thread safe
*/
void init(int curve = mclBn_CurveFp254BNb, int maxUnitSize = MCLBN_FP_UNIT_SIZE);
size_t getOpUnitSize();
void getCurveOrder(std::string& str);
void getFieldOrder(std::string& str);

class SecretKey;
class PublicKey;
class Signature;
class Id;

/*
	the value of secretKey and Id must be less than
	r = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
	sizeof(uint64_t) * keySize byte
*/
const size_t keySize = MCLBN_FP_UNIT_SIZE;

typedef std::vector<SecretKey> SecretKeyVec;
typedef std::vector<PublicKey> PublicKeyVec;
typedef std::vector<Signature> SignatureVec;
typedef std::vector<Id> IdVec;

inline std::string unicode_to_hex(std::string const & input)
{
    static const char* const lut = "0123456789abcdef";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

inline std::string hex_to_unicode(std::string const & input)
{
    std::string output;

    assert((input.length() % 2) == 0);

    size_t cnt = input.length() / 2;

    output.reserve(cnt);
    for (size_t i = 0; cnt > i; ++i) {
        uint32_t s = 0;
        std::stringstream ss;
        ss << std::hex << input.substr(i * 2, 2);
        ss >> s;

        output.push_back(static_cast<unsigned char>(s));
    }
    return output;
}

class Id {
	blsId self_;
	friend class PublicKey;
	friend class SecretKey;
	template<class T, class G> friend struct WrapArray;
	impl::Id& getInner() { return *reinterpret_cast<impl::Id*>(this); }
	const impl::Id& getInner() const { return *reinterpret_cast<const impl::Id*>(this); }
public:
	Id(unsigned int id = 0);
	bool operator==(const Id& rhs) const;
	bool operator!=(const Id& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const Id& id);
	friend std::istream& operator>>(std::istream& is, Id& id);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	bool isZero() const;
	/*
		set p[0, .., keySize)
		@note the value must be less than r
	*/
	void set(const uint64_t *p);
	// bufSize is truncted/zero extended to keySize
	void setLittleEndian(const void *buf, size_t bufSize);
};

/*
	s ; secret key
*/
class SecretKey {
	blsSecretKey self_;
	template<class T, class G> friend struct WrapArray;
	impl::SecretKey& getInner() { return *reinterpret_cast<impl::SecretKey*>(this); }
	const impl::SecretKey& getInner() const { return *reinterpret_cast<const impl::SecretKey*>(this); }
public:
	SecretKey() : self_() {}
	bool operator==(const SecretKey& rhs) const;
	bool operator!=(const SecretKey& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const SecretKey& sec);
	friend std::istream& operator>>(std::istream& is, SecretKey& sec);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	/*
		initialize secretKey with random number and set id = 0
	*/
	void init();
	/*
		set secretKey with p[0, .., keySize) and set id = 0
		@note the value must be less than r
	*/
	void set(const uint64_t *p);
	// bufSize is truncted/zero extended to keySize
	void setLittleEndian(const void *buf, size_t bufSize);
	// set hash of buf
	void setHashOf(const void *buf, size_t bufSize);
	void getPublicKey(PublicKey& pub) const;
	// constant time sign
	void sign(Signature& sig, const std::string& m) const;
	/*
		make Pop(Proof of Possesion)
		pop = prv.sign(pub)
	*/
	void getPop(Signature& pop) const;
	/*
		make [s_0, ..., s_{k-1}] to prepare k-out-of-n secret sharing
	*/
	void getMasterSecretKey(SecretKeyVec& msk, size_t k) const;
	/*
		set a secret key for id > 0 from msk
	*/
	void set(const SecretKeyVec& msk, const Id& id)
	{
		set(msk.data(), msk.size(), id);
	}
	/*
		recover secretKey from k secVec
	*/
	void recover(const SecretKeyVec& secVec, const IdVec& idVec);
	/*
		add secret key
	*/
	void add(const SecretKey& rhs);

	// the following methods are for C api
	/*
		the size of msk must be k
	*/
	void set(const SecretKey *msk, size_t k, const Id& id);
	void recover(const SecretKey *secVec, const Id *idVec, size_t n);

	std::string to_string () const
	{
		std::string s;
		getStr(s, mcl::IoMode::IoSerialize);
		return bls::unicode_to_hex(s);
	}

    void from_string(const string & s)
    {
        setStr(bls::hex_to_unicode(s), mcl::IoMode::IoSerialize);
    }

	void serialize(string & s) const
	{
		getStr(s, mcl::IoMode::IoSerialize);
	}

    template<size_t len>
    void serialize(std::array<unsigned char, len> & arr) const
    {
        std::string prv_str;
        serialize(prv_str);
        memcpy(arr.data(), prv_str.data(), len);
    }

	void deserialize(const string & s)
	{
		setStr(s, mcl::IoMode::IoSerialize);
	}
};

/*
	sQ ; public key
*/
class PublicKey {
	blsPublicKey self_;
	friend class SecretKey;
	friend class Signature;
	template<class T, class G> friend struct WrapArray;
	impl::PublicKey& getInner() { return *reinterpret_cast<impl::PublicKey*>(this); }
	const impl::PublicKey& getInner() const { return *reinterpret_cast<const impl::PublicKey*>(this); }
public:
	PublicKey() : self_() {resetAggPart();}
	bool operator==(const PublicKey& rhs) const;
	bool operator!=(const PublicKey& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const PublicKey& pub);
	friend std::istream& operator>>(std::istream& is, PublicKey& pub);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	/*
		set public for id from mpk
	*/
	void set(const PublicKeyVec& mpk, const Id& id)
	{
		set(mpk.data(), mpk.size(), id);
	}
	/*
		recover publicKey from k pubVec
	*/
	void recover(const PublicKeyVec& pubVec, const IdVec& idVec);
	/*
		add public key
	*/
	void add(const PublicKey& rhs);

	// the following methods are for C api
	void set(const PublicKey *mpk, size_t k, const Id& id);
	void recover(const PublicKey *pubVec, const Id *idVec, size_t n);

	/****************************************************************/
	//Peng
	mclBnFr t; //TODO, only compute once, need to figure out when to recompute
	mclBnG2 aggPart;
	void resetAggPart()
	{
		mclBnFr_clear(&t);
		mclBnG2_clear(&aggPart);
	}

	PublicKey(const PublicKey & other)
	: self_(other.self_)
	{
		resetAggPart();
	}

	PublicKey & operator=(const PublicKey &other)
	{
        if(&other == this)
            return *this;
		memcpy(&self_, &other.self_, sizeof(self_));
		resetAggPart();
		return *this;
	}

	bool isAggSet()
	{
		return ! mclBnFr_isZero(&t);
	}

	bool computeAgg()
	{
#ifdef HASH_2nd_128BIT
		std::string str;
		getStr(str, bls::IoFixedByteSeq);
		mclBnFr temp;
		int res = mclBnFr_setHash128Of(&temp, str.c_str(), str.size());//TODO check hash function used and size so that t in {1,2,...2^128}
		if(res)
		{
			cerr << __func__ << ", mclBnFr_setHashOf error, res=" << res << endl;
			return false;
		}
		mclBnFr one;//TODO global
		mclBnFr_setInt32(&one, 1);
		mclBnFr_add(&t, &temp, &one);

		mclBnG2_mul(&aggPart, &self_.v, &t);
		return true;
#else
		mclBnFr_setInt32(&t, 1); //set t to non-zero
		aggPart = self_.v;
		if(memcmp((void*)&aggPart, (void*)&self_.v, sizeof(aggPart)))
		{
			cerr << __func__ << ", memcmp((void*)&aggPart, (void*)&self_.v, sizeof(aggPart)) error" << endl;
			exit(-1);
		}
		return true;
#endif
	}

	static bool readyToAggregate(PublicKeyVec& mpk)
	{
		for(auto &x : mpk)
		{
			if(! x.isAggSet())
			{
				if( ! x.computeAgg())
				{
					cerr << __func__ << ", ! x.computeAgg() error" << endl;
					return false;
				}
			}
		}
		return true;
	}

	bool aggregateFrom(PublicKeyVec& mpk)
	{
		if(mpk.empty() || !readyToAggregate(mpk))
		{
			cerr << __func__ << ", mpk.empty() || !readyToAggregate(mpk) error" << endl;
			return false;
		}

		int vs = mpk.size();
		if(vs == 1)
		{
			//			self_.v = mpk[0].aggPart; //TODO verify assign op
			//			if(memcmp((void*)&mpk[0].aggPart, (void*)&self_.v, sizeof(self_.v)))
			//			{
			//				cerr << __func__ << ", memcmp((void*)&mpk[0].aggPart, (void*)&self_.v, sizeof(self_.v)) error" << endl;
			//				exit(-1);
			//			}
			memcpy(&self_.v, &mpk[0].aggPart, sizeof(self_.v));
		}
		else
		{
			mclBnG2 z[2];
			mclBnG2 *x = &mpk[0].aggPart;
			mclBnG2 *y = &mpk[1].aggPart;
			mclBnG2_add(&z[0], x, y);
			for(int i = 2; i < vs; ++i)
			{
				x = & mpk[i].aggPart;
				y = & z[i%2];
				mclBnG2_add(&z[(i+1)%2], x, y); //TODO double check
			}

			//self_.v = z[vs%2];
			memcpy(&self_.v, &z[vs%2], sizeof(self_.v));
		}

		return true;
	}

	std::string to_string () const
	{
		std::string s;
        serialize(s);
		return unicode_to_hex(s);
	}

	void from_string(const string & s)
    {
        setStr(bls::hex_to_unicode(s), mcl::IoMode::IoSerialize);
    }

	void serialize(string & s) const
	{
		getStr(s, mcl::IoMode::IoSerialize);
	}

    template<size_t len>
	void serialize(std::array<unsigned char, len> & arr) const
    {
	    std::string pub_str;
	    serialize(pub_str);
	    memcpy(arr.data(), pub_str.data(), len);
    }

	void deserialize(const string & s)
	{
		setStr(s, mcl::IoMode::IoSerialize);
	}
	/****************************************************************/
};

class KeyPair
{
public:
	KeyPair ()
	{
		prv.init();
		prv.getPublicKey(pub);
	}

	KeyPair (std::string const & s)
	{
		prv.setStr(s, mcl::IoMode::IoSerialize);
		prv.getPublicKey(pub);
	}

	KeyPair (std::array<unsigned char, 32> const & raw)
    {
	    std::string str;
	    str.reserve(32);
	    for (auto const & i : raw)
        {
	        str.push_back((char)i);
        }
	    prv.setStr(str, mcl::IoMode::IoSerialize);
	    prv.getPublicKey(pub);
    }

	bls::SecretKey prv;
	bls::PublicKey pub;
};

/*
	s H(m) ; signature
*/
class Signature {
	blsSignature self_;
	friend class SecretKey;
	template<class T, class G> friend struct WrapArray;
	impl::Signature& getInner() { return *reinterpret_cast<impl::Signature*>(this); }
	const impl::Signature& getInner() const { return *reinterpret_cast<const impl::Signature*>(this); }
public:
	Signature() : self_() {resetAggPart();}
	bool operator==(const Signature& rhs) const;
	bool operator!=(const Signature& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const Signature& s);
	friend std::istream& operator>>(std::istream& is, Signature& s);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	bool verify(const PublicKey& pub, const std::string& m) const;
	/*
		verify self(pop) with pub
	*/
	bool verify(const PublicKey& pub) const;
	/*
		recover sig from k sigVec
	*/
	void recover(const SignatureVec& sigVec, const IdVec& idVec);
	/*
		add signature
	*/
	void add(const Signature& rhs);

	// the following methods are for C api
	void recover(const Signature* sigVec, const Id *idVec, size_t n);

	/****************************************************************/
	//Peng
	mclBnG1 aggPart;

	Signature(const Signature& other)
	: self_(other.self_)
	{
		resetAggPart();
	}

	Signature & operator=(const Signature &other)
	{
        if(&other == this)
            return *this;
		memcpy(&self_, &other.self_, sizeof(self_));
		resetAggPart();
		return *this;
	}

	void resetAggPart()
	{
		mclBnG1_clear(&aggPart);
	}
	bool isAggSet()
	{
		return ! mclBnG1_isZero(&aggPart);
	}

	bool computeAgg(const PublicKey& pub) //TODO assuming pub is agg-ready
	{
#ifdef HASH_2nd_128BIT
		mclBnG1_mul(&aggPart, &self_.v, &pub.t);
#else
		aggPart = self_.v;
		if(memcmp((void*)&aggPart, (void*)&self_.v, sizeof(aggPart)))
		{
			cerr << __func__ << ", Signature memcmp((void*)&aggPart, (void*)&self_.v, sizeof(aggPart)) error" << endl;
			exit(-1);
		}
#endif
		return true;
	}

	//TODO private?
	static bool readyToAggregate(SignatureVec& sigVec, PublicKeyVec& mpk)
	{
		int svs = sigVec.size();
		for(int i = 0; i < svs; ++i)
		{
			if(! sigVec[i].isAggSet())
			{
				if( ! sigVec[i].computeAgg(mpk[i]))
				{
					cerr << __func__ << ", ! sigVec[i].computeAgg(mpk[0]) error" << endl;
					return false;
				}
			}
		}
		return true;
	}

	bool aggregateFrom(SignatureVec& sigVec, PublicKeyVec& mpk) //TODO assuming sig and pk indices match
	{
		int svs = sigVec.size();
		int pvs = mpk.size();

		if(sigVec.empty() || mpk.empty() || svs != pvs)
		{
			cerr << __func__ << ", sigVec.empty() || mpk.empty() || svs != pvs error" << endl;
			return false;
		}

		if( !PublicKey::readyToAggregate(mpk) )
		{
			cerr << __func__ << ", !PublicKey::readyToAggregate(mpk) error" << endl;
			return false;
		}

		if( !Signature::readyToAggregate(sigVec, mpk))
		{
			cerr << __func__ << ", !Signature::readyToAggregate(sigVec, mpk) error" << endl;
			return false;
		}

		if(svs == 1)
		{
			//			self_.v = sigVec[0].aggPart; //TODO verify assign op
			//			if(memcmp((void*)&sigVec[0].aggPart, (void*)&self_.v, sizeof(aggPart)))
			//			{
			//				cerr << __func__ << ", Signature memcmp((void*)&aggPart, (void*)&self_.v, sizeof(aggPart)) error" << endl;
			//				exit(-1);
			//			}
			memcpy(&self_.v, &sigVec[0].aggPart, sizeof(self_.v));
		}
		else
		{
			mclBnG1 z[2];
			mclBnG1 *x = &sigVec[0].aggPart;
			mclBnG1 *y = &sigVec[1].aggPart;
			mclBnG1_add(&z[0], x, y);
			for(int i = 2; i < svs; ++i)
			{
				x = & sigVec[i].aggPart;
				y = & z[i%2];
				mclBnG1_add(&z[(i+1)%2], x, y); //TODO double check
			}
			//self_.v = z[svs%2];
			//			if(memcmp((void*)&z[svs%2], (void*)&self_.v, sizeof(self_.v)))
			//			{
			//				cerr << __func__ << ", Signature memcmp((void*)&aggPart, (void*)&self_.v, sizeof(aggPart)) error" << endl;
			//				exit(-1);
			//			}

			memcpy(&self_.v, &z[svs%2], sizeof(self_.v));
		}

		return true;
	}

	std::string to_string () const{
		std::string s;
		getStr(s, mcl::IoMode::IoHex);
		return s;
	}
	void serialize(string & s)
	{
		getStr(s, mcl::IoMode::IoSerialize);
	}

	void deserialize(const string & s)
	{
		setStr(s, mcl::IoMode::IoSerialize);
	}
	/****************************************************************/
};

/*
	make master public key [s_0 Q, ..., s_{k-1} Q] from msk
*/
inline void getMasterPublicKey(PublicKeyVec& mpk, const SecretKeyVec& msk)
{
	const size_t n = msk.size();
	mpk.resize(n);
	for (size_t i = 0; i < n; i++) {
		msk[i].getPublicKey(mpk[i]);
	}
}

/*
	make pop from msk and mpk
*/
inline void getPopVec(SignatureVec& popVec, const SecretKeyVec& msk)
{
	const size_t n = msk.size();
	popVec.resize(n);
	for (size_t i = 0; i < n; i++) {
		msk[i].getPop(popVec[i]);
	}
}

inline Signature operator+(const Signature& a, const Signature& b) { Signature r(a); r.add(b); return r; }
inline PublicKey operator+(const PublicKey& a, const PublicKey& b) { PublicKey r(a); r.add(b); return r; }
inline SecretKey operator+(const SecretKey& a, const SecretKey& b) { SecretKey r(a); r.add(b); return r; }

} //bls
