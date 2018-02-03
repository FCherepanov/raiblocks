#pragma once
#include <unordered_map>

const int result_ok = 0;
const int result_err_privateKey_or_account = 1;//"Private key or local wallet and account required"
const int result_err_invalid_block_type = 2;//"Invalid block type"
const int result_err_no_enough_dest_fields = 3;//"Destination account, previous hash, current balance and amount required"
const int result_err_account_and_source_hash_required = 4;//"Representative account and source hash required"
const int result_err_hash_and_source_required = 5;//"Previous hash and source hash required"
const int result_err_insufficient_balance = 6;//"Insufficient balance"
const int result_err_need_work = 7;//"Need work"
const int result_err_unknown = 100;//"Unknown error"

extern "C" char * key_create();

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
	int * errorCode);