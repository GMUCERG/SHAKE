-- =====================================================================
-- Copyright © 2010-2012 by Cryptographic Engineering Research Group (CERG),
-- ECE Department, George Mason University
-- Fairfax, VA, U.S.A.
-- =====================================================================

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.std_logic_unsigned.all;
use ieee.std_logic_arith.all;						 

entity keccak_bytepad is
	generic( w:integer:=64);
    Port ( din : in  std_logic_vector (w-1 downto 0);
           dout : out  std_logic_vector (w-1 downto 0);
           sel_pad_location 	: in  std_logic_vector(w/8-1 downto 0);
		   sel_din 			: in  std_logic_vector(w/8-1 downto 0);
		   last_word : in std_logic);
end keccak_bytepad;

architecture struct of keccak_bytepad is			
	type byte_pad_type is array (w/8-1 downto 0) of std_logic_vector(7 downto 0);
	signal byte_pad_wire	: byte_pad_type;   
		
	signal sel_last_mux : std_logic_vector(1 downto 0);
begin	 																	 
	byte_pad_gen : for i in w/8-1 downto 1 generate
		byte_pad_wire(i)<= X"01" when sel_pad_location(i) = '1' else X"00";
		dout(8*(i+1)-1 downto 8*i) <= din(8*(i+1)-1 downto 8*i) when sel_din(i) = '1' else byte_pad_wire(i);		
	end generate;
	
	sel_last_mux <=  last_word & sel_pad_location(0);
	with sel_last_mux(1 downto 0) select
	byte_pad_wire(0)  <= x"00" when "00",
						 x"01" when "01",
						 x"80" when "10",
						 x"81" when OTHERS;		 
	dout(7 downto 0)<=din(7 downto 0) when sel_din(0) = '1' else byte_pad_wire(0);
end struct;

														