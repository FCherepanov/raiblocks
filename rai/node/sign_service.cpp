#include <rai/node/sign_service.hpp>
#include <ed25519-donna/ed25519.h>
#include <rai/lib/blocks.hpp>
#include <rai/secure.hpp>

extern "C" char * key_create()
{
	rai::keypair pair;
	std::string private_key = pair.prv.data.to_string ();
	std::string account = pair.pub.to_account ();
	std::string res = private_key+":"+account;
	return strcpy(new char[res.size()], res.c_str());
}

std::string block_create (
	std::string type,
	std::string account_text,
	std::string destination_text,
	std::string source_text,
	std::string amount_text,
	std::string work_text,
	std::string key_text,
	std::string previous_text,
	std::string balance_text,
	int* errorCode);

std::string getString(char * str)
{
	if (str == NULL)
	{
		return "";
	}
	
	std::string res(str);
	return res;
}

extern "C" char * block_create_c (
	char * type_text, 
	char * account_text,
	char * destination_text,
	char * source_text,
	char * amount_text,
	char * work_text,
	char * key_text,
	char * previous_text,
	char * balance_text,
	int * errorCode)
{
	std::string type = getString(type_text);
	std::string account = getString(account_text);
	std::string destination = getString(destination_text);
	std::string source = getString(source_text);
	std::string amount = getString(amount_text);
	std::string work = getString(work_text);
	std::string key = getString(key_text);
	std::string previous = getString(previous_text);
	std::string balance = getString(balance_text);

	*errorCode = result_ok;
	std::string res = block_create(type,account,destination,source,amount,work,key,previous,balance,errorCode);
    return strcpy(new char[res.size()], res.c_str());
}

std::string block_create (
	std::string type,
	std::string account_text,
	std::string destination_text,
	std::string source_text,
	std::string amount_text,
	std::string work_text,
	std::string key_text,
	std::string previous_text,
	std::string balance_text,
	int* errorCode)
{
	rai::uint256_union account (0);
	account.decode_account (account_text);
	rai::uint256_union destination (0);
	destination.decode_account (destination_text);
	rai::block_hash source (0);
	source.decode_hex (source_text);
	rai::uint128_union amount (0);
	amount.decode_dec (amount_text);
	uint64_t work (0);
	rai::from_string_hex (work_text, work);

	rai::raw_key prv;
	prv.data.clear ();
	prv.data.decode_hex (key_text);

	rai::uint256_union previous (0);
	rai::uint128_union balance (0);

	previous.decode_hex (previous_text);
	balance.decode_dec (balance_text);

	if (prv.data != 0)
	{

		rai::uint256_union pub;
		ed25519_publickey (prv.data.bytes.data (), pub.bytes.data ());
		if (type == "open")
		{
			if (account != 0 && source != 0)
			{
				if (work == 0)
				{
					*errorCode = result_err_need_work;
					return "";
				}

				rai::open_block open (source, account, pub, prv, pub, work);
				std::string signature_l;
				open.signature.encode_hex (signature_l);
				return signature_l;
			}
			else
			{
				
				*errorCode = result_err_account_and_source_hash_required;
				return "";
			}
		}
		else if (type == "receive")
		{
			if (source != 0 && previous != 0)
			{
				if (work == 0)
				{
					*errorCode = result_err_need_work;
					return "";
				}
				rai::receive_block receive (previous, source, prv, pub, work);
				std::string signature_l;
				receive.signature.encode_hex (signature_l);
				return signature_l;
			}
			else
			{
				*errorCode = result_err_hash_and_source_required;
				return "";	
			}
		}
		else if (type == "send")
		{
			if (destination != 0 && amount != 0)
			{
				if (balance.number () >= amount.number ())
				{
					if (work == 0)
					{
						*errorCode = result_err_need_work;
						return "";
					}

					rai::send_block send (previous, destination, balance.number () - amount.number (), prv, pub, work);
					std::string signature_l;
					send.signature.encode_hex (signature_l);
					return signature_l;
				}
				else
				{
					*errorCode = result_err_insufficient_balance;
					return "";
				}
			}
			else
			{
				*errorCode = result_err_no_enough_dest_fields;
			}
		}
		else
		{
			*errorCode = result_err_invalid_block_type;
		}
	}
	else
	{
		*errorCode = result_err_privateKey_or_account;
	}
}