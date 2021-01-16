-- =====================================================================
-- Copyright © 2017-2018 by Cryptographic Engineering Research Group (CERG),
-- ECE Department, George Mason University
-- Fairfax, VA, U.S.A.
-- Author: Farnoud Farahmand
-- =====================================================================
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use ieee.std_logic_unsigned.all;
library work;
use work.design_pkg.all;
use work.CAESAR_LWAPI_pkg.all;

entity cshake_preprocessor is
    generic(
        W    : integer := 64;
        NPUB_SIZE     : integer := 16;
        TAG_SIZE      : integer := 16;
        COUNTER_SIZE  : integer := 10;
        FIFO_DEPTH    : integer := 5
    );
    port(
        rst         : in std_logic;
        clk         : in std_logic;
        --! FIFO Input
        write_in    : in std_logic;
        full_in	    : out std_logic;
        d_in        : in std_logic_vector(W-1 downto 0);
        --! FIFO Output
        write_out   : out std_logic;
        full_out    : in std_logic;
        d_out       : out std_logic_vector(W-1 downto 0);
        --! Control Reg
        variant_reg : out std_logic_vector(3 downto 0)
    );
end cshake_preprocessor;

architecture behavioral of cshake_preprocessor is

    --! STATE
    type t_state is (S_RESET, S_INST, S_HDR_NPUB, S_DATA_NPUB, S_HDR_AD,
        S_HDR_PT, S_DATA_ENC, S_INST_DEC, S_DATA_DEC, S_HDR_LDKEY, S_DATA_KEY,
        S_WAIT_DO);
    signal state            : t_state;
    signal state_next       : t_state;
    --! PDO_FIFO
    signal pdo_fifo_read   : std_logic;
    signal pdo_fifo_write  : std_logic;
    signal pdo_fifo_empty  : std_logic;
    signal pdo_fifo_full   : std_logic;
    signal pdo_a_fifo_din  : std_logic_vector(DATA_WIDTH-1 downto 0);
    signal pdo_b_fifo_din  : std_logic_vector(DATA_WIDTH-1 downto 0);
    --! DO_FIFO
    signal do_fifo_read   : std_logic;
    signal do_fifo_write  : std_logic;
    signal do_fifo_empty  : std_logic;
    signal do_fifo_full   : std_logic;
    -- signal do_a_fifo_din  : std_logic_vector(DATA_WIDTH-1 downto 0);
    -- signal do_b_fifo_din  : std_logic_vector(DATA_WIDTH-1 downto 0);
    signal do_fifo_din  : std_logic_vector(DATA_WIDTH-1 downto 0);
    --! Controller
    signal ctrl_pdo_fwrite: std_logic;
    signal ctrl_pdo_a_fdin: std_logic_vector(DATA_WIDTH-1 downto 0);
    signal ctrl_pdo_b_fdin: std_logic_vector(DATA_WIDTH-1 downto 0);
    signal ctrl_do_fwrite : std_logic;
    signal ctrl_do_a_fdin : std_logic_vector(DATA_WIDTH-1 downto 0);
    signal ctrl_do_b_fdin : std_logic_vector(DATA_WIDTH-1 downto 0);
    signal ctrl_rdi_tready: std_logic;
    signal sel_do_fifo    : std_logic;
    signal sel_pdo_fifo   : std_logic;
    signal sel_rdo        : std_logic;
    signal pdo_fifo_write_s : std_logic;
    signal sel_bypass     : std_logic;
    signal sel_pdi_tdata  : std_logic;

    signal count_r        : std_logic_vector(COUNTER_SIZE-1 downto 0);
    signal count_next     : std_logic_vector(COUNTER_SIZE-1 downto 0);
    signal do_count_r     : std_logic_vector(COUNTER_SIZE-1 downto 0);
    signal do_count_next  : std_logic_vector(COUNTER_SIZE-1 downto 0);
    signal en_data_size   : std_logic;
    signal data_size_r    : std_logic_vector(15 downto 0);
    signal en_instruction : std_logic;
    signal instruction_r  : std_logic_vector(3 downto 0);
    signal pdi_tdata_s    : std_logic_vector(DATA_WIDTH-1 downto 0);
    signal pdi_tdata_mod  : std_logic_vector(DATA_WIDTH-1 downto 0);


    constant w_size := (w-4)/2;
    signal variant_next, variant_r   : std_logic_vector(3 downto 0);
    signal in_size_next, in_size_r   : std_logic_vector(w_size -1 downto 0);
    signal out_size_next, out_size_r : std_logic_vector(w_size -1 downto 0);
    signal N_size_next, N_size_r     : std_logic_vector(w/2 -1 downto 0);
    signal S_size_next, S_size_r     : std_logic_vector(w/2 -1 downto 0);
    signal buf_next, buf_r           : std_logic_vector(40 -1 downto 0);
    signal num_blk                   : integer;


begin

    p_fsm: process(clk)
    begin
        if rising_edge(clk) then
            if (rst = '1') then
                state <= S_RESET;
                --data_size_r   <= (others=>'0');
                variant_r <= (others=>'0');
            else
                state       <= state_next;
                variant_r   <= variant_next;
            end if;
            in_size_r       <= in_size_next;
            out_size_r      <= out_size_next;
            N_size_r        <= N_size_next;
            S_size_r        <= S_size_next;
            buf_r           <= buf_next;


            count_r         <= count_next;
            do_count_r      <= do_count_next;
            if (en_data_size = '1') then
                data_size_r <= data_size;
            end if;
            if (en_instruction = '1') then
                instruction_r <= instruction;
            end if;
        end if;
    end process;

    p_comb: process(state, write_in, full_out)
    begin
        --! Default values
        state_next      <= state;
        count_next      <= count_r;

        variant_next    <= variant_r;
        in_size_next    <= in_size_r;
        out_size_next   <= out_size_r;
        N_size_next     <= N_size_r;
        S_size_next     <= S_size_r;
        buf_next        <= buf_r;
        error           <= '0';
        full_in         <= '1';
        write_out       <= '0';




        en_data_size    <= '0';
        sel_do_fifo     <= '0';
        sel_pdo_fifo    <= '0';


        case state is
            when S_RESET =>
                full_in  <= '0';
                if (write_in = '1') then
                    count_next	   <= (others => '0');
                    variant_next   <= d_in(w-1 downto w-4);
                    out_size_next  <= d_in(w-5 downto w-(w_size-4);
                    in_size_next   <= d_in(w-(w_size-5 downto 0);
                    state_next     <= S_INST;
                end if;

            when S_INST =>

                if (variant_r = "0000") or (variant_r = "0001") =>
                --! SHAKE-128 or SHAKE-256
                    d_out <= '1' & '0' & out_size_r(w_size-1 downto 0) & "00" &
                        in_size_r(w_size-1 downto 0);
                    if (full_out = '0') then
                        write_out       <= '1';
                        state_next      <= S_TRANSFER_DATA;
                    end if;
                else
                --! cSHAKE-128 or cSHAKE-256
                    full_in  <= '0';
                    if (write_in = '1') then
                        N_size_next  <= d_in(w-1 downto w/2);
                        S_size_next  <= d_in(w/2 -1 downto 0);
                        if (N_size_next = 0) and (S_size_next = 0) then
                            state_next   <= S_TRANSFER_DATA;
                        else
                            state_next   <= S_LEFT_ENCODE_N;
                        end if;
                    end if;
                end if;

            when S_TRANSFER_DATA =>
                full_in   <= full_out;
                d_out     <= d_in;
                write_out <= write_in;
                if (count_r = num_blk-1) then
                    state_next <= S_RESET;
                else
                    count_next <= count_r + 1;
                end if;


            when S_LEFT_ENCODE_N =>
                if (N_size_r(31 downto 24) /= 0) then
                    count_next <= count_r + 5 + to_integer(N_size_r(31 downto 3));
                    buf_next   <= x"04" & N_size_r;
                elsif (N_size_r(23 downto 16) /= 0) then
                    count_next <= count_r + 4 + to_integer(N_size_r(31 downto 3));
                    buf_next   <= x"00" & x"03" & N_size_r(23 downto 0);
                elsif (N_size_r(15 downto 8) /= 0) then
                    count_next <= count_r + 3 + to_integer(N_size_r(31 downto 3));
                    buf_next   <= x"0000" & x"02" & N_size_r(15 downto 0);
                elsif (N_size_r(7 downto 0) /= 0) then
                    count_next <= count_r + 2 + to_integer(N_size_r(31 downto 3));
                    buf_next   <= x"000000" & x"01" & N_size_r(7 downto 0);
                end if;
                state_next <=

            when S_DATA_KEY =>
                if (rmdi_tvalid = '1') and (sdi_tvalid = '1') then
                    sdo_tvalid   <= '1';
                    if (sdo_tready = '1') then
                        rmdi_tready  <= '1';
                        sdi_tready   <= '1';
                        sdo_a_tdata  <= sdi_tdata xor rmdi_tdata;
                        sdo_b_tdata  <= rmdi_tdata;
                        if (count_r = (128/DATA_WIDTH)-1) then
                            done     <= '1';
                            count_next     <= (others => '0');
                            state_next     <= S_RESET;
                        else
                            count_next     <= count_r + 1;
                        end if;
                    end if;
                end if;


            when others =>
                error <= '1';
                state_next <= S_RESET;

        end case;
    end process;

    --! Datapath

    variant_reg <= variant_r;

    num_blk  <= divceil(to_integer(in_size_r), (w/8));








    PDO_a_FIFO: entity work.fifo(structure)
    generic map(
        G_LOG2DEPTH    => FIFO_DEPTH,
        G_W            => DATA_WIDTH
    )
    port map (
        clk              => clk,
        rstn             => not(rst),
        write            => pdo_fifo_write_s,
        read             => pdo_fifo_read,
        di_data          => pdo_a_fifo_din,
        do_data          => pdo_a_tdata,
        almost_full      => open,
        full             => pdo_fifo_full,
        empty            => pdo_fifo_empty,
        almost_empty     => open
    );

    PDO_b_FIFO: entity work.fifo(structure)
    generic map(
        G_LOG2DEPTH    => FIFO_DEPTH,
        G_W            => DATA_WIDTH
    )
    port map (
        clk              => clk,
        rstn             => not(rst),
        write            => pdo_fifo_write_s,
        read             => pdo_fifo_read,
        di_data          => pdo_b_fifo_din,
        do_data          => pdo_b_tdata,
        almost_full      => open,
        full             => open,
        empty            => open,
        almost_empty     => open
    );
    --! PDI/PDO Bus Interconnect
    --! Input Bus
    pdo_tvalid     <= not pdo_fifo_empty;
    pdo_fifo_read  <= (not pdo_fifo_empty) and (pdo_tready);
    --! Output Bus
    pdi_tdata_s <= pdi_tdata_mod when sel_pdi_tdata = '1' else pdi_tdata;

    pdo_a_fifo_din   <= ctrl_pdo_a_fdin when sel_pdo_fifo = '1' else
        (pdi_tdata_s xor rmdi_tdata);

    pdo_b_fifo_din   <= ctrl_pdo_b_fdin when sel_pdo_fifo = '1' else rmdi_tdata;

    pdo_fifo_write <= ctrl_pdo_fwrite when sel_pdo_fifo = '1' else
        (pdi_tvalid and (not pdo_fifo_full) and rmdi_tvalid);

    pdi_tready     <= '0' when sel_pdo_fifo = '1' else (not pdo_fifo_full)and rmdi_tvalid;
    --! to bypass the status word
    pdo_fifo_write_s <= '0' when sel_bypass = '1' else pdo_fifo_write;

    DO_FIFO: entity work.fifo(structure)
    generic map(
        G_LOG2DEPTH    => FIFO_DEPTH,
        G_W            => DATA_WIDTH
    )
    port map (
        clk              => clk,
        rstn             => not(rst),
        write            => do_fifo_write,
        read             => do_fifo_read,
        di_data          => do_fifo_din,
        do_data          => do_tdata,
        almost_full      => open,
        full             => do_fifo_full,
        empty            => do_fifo_empty,
        almost_empty     => open
    );

--    DO_b_FIFO: entity work.fifo(structure)
--    generic map(
--        G_LOG2DEPTH    => FIFO_DEPTH,
--        G_W            => DATA_WIDTH
--    )
--    port map (
--        clk              => clk,
--        rstn             => not(rst),
--        write            => do_fifo_write,
--        read             => do_fifo_read,
--        di_data          => do_b_fifo_din,
--        do_data          => do_b_tdata,
--        almost_full      => open,
--        full             => open,
--        empty            => open,
--        almost_empty     => open
--    );
    --! DI/DO Bus Interconnect
    --! Input Bus
    do_tvalid     <= not do_fifo_empty;
    do_fifo_read  <= (not do_fifo_empty) and (do_tready);
    --! Output Bus
    do_fifo_din   <= (ctrl_do_a_fdin xor ctrl_do_b_fdin) when sel_do_fifo = '1'
        else (di_a_tdata xor di_b_tdata);
    --do_a_fifo_din   <= ctrl_do_a_fdin when sel_do_fifo = '1' else di_a_tdata;
    --do_b_fifo_din   <= ctrl_do_b_fdin when sel_do_fifo = '1' else di_b_tdata;
    do_fifo_write <= ctrl_do_fwrite when sel_do_fifo = '1' else
        (di_tvalid and (not do_fifo_full));
    di_tready     <= '0' when sel_do_fifo = '1' else (not do_fifo_full);

    --! RDI/RDO Bus Interconnect
    rdo_tvalid <= '0' when sel_rdo = '1' else rdi_tvalid;
    rdo_tdata  <= (others => '0') when sel_rdo = '1' else rdi_tdata;
    rdi_tready <= ctrl_rdi_tready when sel_rdo = '1' else rdo_tready;

end behavioral;
