-- =====================================================================
-- Copyright © 2010-2012 by Cryptographic Engineering Research Group (CERG),
-- ECE Department, George Mason University
-- Fairfax, VA, U.S.A.
-- =====================================================================

-- Possible generics values:
-- hs = {HASH_SIZE_256, HASH_SIZE_512}

library ieee;
use ieee.std_logic_1164.all;
use work.sha3_pkg.all;
use work.keccak_pkg.all;


entity keccak_top is
generic (HS : integer := HASH_SIZE_256);
port (
		rst 			: in std_logic;
		clk 			: in std_logic;
		src_ready 		: in std_logic;
		src_read  		: out std_logic;
		dst_ready 		: in std_logic;
		dst_write 		: out std_logic;
		din				: in std_logic_vector(w-1 downto 0);
		dout			: out std_logic_vector(w-1 downto 0));
end keccak_top;


architecture structure of keccak_top is
	constant capacity : integer := get_keccak_capacity( HS );
    constant version : integer := SHA3_ROUND3;
	signal ein: std_logic;
	signal final_segment : std_logic;
	signal sel_xor, sel_final, wr_state, en_ctr :std_logic;
	signal c, d:  std_logic_vector(31 downto 0);
	signal en_len, en_output_len, ld_rdctr, en_rdctr, sel_piso, last_block,
        wr_piso  : std_logic;

	-- pad
	signal spos : std_logic_vector(1 downto 0);
	signal sel_dec_size, clr_len : std_logic;
	signal last_word : std_logic;
begin

	control_gen : entity work.keccak_control(struct)
		generic map(hs=>HS)
		port map (clk =>clk, rst=>rst, ein=>	ein,
		en_ctr=>en_ctr,   en_len=>en_len, en_output_len=>en_output_len, sel_xor=>sel_xor, sel_final=>sel_final, ld_rdctr=>ld_rdctr,
		en_rdctr=>en_rdctr,  wr_state=>wr_state, sel_out=>sel_piso,final_segment=>final_segment,
		wr_piso=>wr_piso, src_ready=>src_ready,
		src_read=>src_read, dst_ready =>dst_ready,	dst_write=>dst_write, c=>c, d=>d,
		-- pad
		clr_len => clr_len, sel_dec_size => sel_dec_size, last_word => last_word, spos => spos	);


	datapath_gen : entity work.keccak_datapath(struct)
		generic map(hs=>HS, b=>capacity, version=>version)
		port map (clk => clk, rst=>rst, din => din, dout => dout,
		en_len=>en_len, en_output_len=>en_output_len, en_ctr=>en_ctr, ein=>ein, c=>c, d=> d, sel_xor=>sel_xor, sel_final=>sel_final,
		wr_state=>wr_state, ld_rdctr=>ld_rdctr, en_rdctr=>en_rdctr, sel_piso=>sel_piso, wr_piso	=>wr_piso,
		final_segment=>final_segment,
		-- pad
		clr_len => clr_len, sel_dec_size => sel_dec_size, last_word => last_word, spos => spos	);


end structure;
