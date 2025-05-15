<?php

/**
 * See https://developer.valvesoftware.com/wiki/Source_RCON_Protocol for
 * more information about Source RCON Packets
 *
 * PHP Version 7
 *
 * @copyright 2013-2017 Chris Churchwell
 * @author thedudeguy
 * @link https://github.com/thedudeguy/PHP-Minecraft-Rcon
 */

namespace Thedudeguy;

class Rcon
{
    private $host;
    private $port;
    private $password;
    private $timeout;

    private $socket;

    private $authorized = false;
    private $lastResponse = '';

    const PACKET_AUTHORIZE = 5;
    const PACKET_COMMAND = 6;

    const SERVERDATA_AUTH = 3;
    const SERVERDATA_AUTH_RESPONSE = 2;
    const SERVERDATA_EXECCOMMAND = 2;
    const SERVERDATA_RESPONSE_VALUE = 0;

    /**
     * Create a new instance of the Rcon class.
     *
     * @param string $host
     * @param integer $port
     * @param string $password
     * @param integer $timeout
     */
    public function __construct($host, $port, $password, $timeout)
    {
        $this->host = $host;
        $this->port = $port;
        $this->password = $password;
        $this->timeout = $timeout;
    }

    /**
     * Get the latest response from the server.
     *
     * @return string
     */
    public function getResponse()
    {
        return $this->lastResponse;
    }

    /**
     * Connect to a server.
     *
     * @return boolean
     */
    public function connect()
    {
        $this->socket = fsockopen($this->host, $this->port, $errno, $errstr, $this->timeout);

        if (!$this->socket) {
            $this->lastResponse = $errstr;
            return false;
        }

        //set timeout
        stream_set_timeout($this->socket, 3, 0);

        // check authorization
        return $this->authorize();
    }

    /**
     * Disconnect from server.
     *
     * @return void
     */
    public function disconnect()
    {
        if ($this->socket) {
            fclose($this->socket);
        }
    }

    /**
     * True if socket is connected and authorized.
     *
     * @return boolean
     */
    public function isConnected()
    {
        return $this->authorized;
    }

    /**
     * Send a command to the connected server.
     *
     * @param string $command
     *
     * @return boolean|mixed
     */
    public function sendCommand($command)
    {
        if (!$this->isConnected()) {
            return false;
        }

        // send command packet
        $this->writePacket(self::PACKET_COMMAND, self::SERVERDATA_EXECCOMMAND, $command);

        // get response
        $response_packet = $this->readPacket();
        if ($response_packet['id'] == self::PACKET_COMMAND) {
            if ($response_packet['type'] == self::SERVERDATA_RESPONSE_VALUE) {
                $this->lastResponse = $response_packet['body'];

                return $response_packet['body'];
            }
        }

        return false;
    }

    /**
     * Log into the server with the given credentials.
     *
     * @return boolean
     */
    private function authorize()
    {
        $this->writePacket(self::PACKET_AUTHORIZE, self::SERVERDATA_AUTH, $this->password);
        $response_packet = $this->readPacket();

        if ($response_packet['type'] == self::SERVERDATA_AUTH_RESPONSE) {
            if ($response_packet['id'] == self::PACKET_AUTHORIZE) {
                $this->authorized = true;

                return true;
            }
        }

        $this->disconnect();
        return false;
    }

    /**
     * Writes a packet to the socket stream.
     *
     * @param $packetId
     * @param $packetType
     * @param string $packetBody
     *
     * @return void
     */
    private function writePacket($packetId, $packetType, $packetBody)
    {
        /*
		Size			32-bit little-endian Signed Integer	 	Varies, see below.
		ID				32-bit little-endian Signed Integer		Varies, see below.
		Type	        32-bit little-endian Signed Integer		Varies, see below.
		Body		    Null-terminated ASCII String			Varies, see below.
		Empty String    Null-terminated ASCII String			0x00
		*/

        //create packet
        $packet = pack('VV', $packetId, $packetType);
        $packet = $packet . $packetBody . "\x00";
        $packet = $packet . "\x00";

        // get packet size.
        $packet_size = strlen($packet);

        // attach size to packet.
        $packet = pack('V', $packet_size) . $packet;

        // write packet.
        fwrite($this->socket, $packet, strlen($packet));
    }

    private function readPacket()
    {
        $response = '';
        $packetId = null;
        $packetType = null;

        stream_set_timeout($this->socket, 2);

        while (true) {
            // Read 4 bytes for packet size
            $size_data = fread($this->socket, 4);
            if (strlen($size_data) !== 4) {
                break;
            }

            $size = unpack('V1size', $size_data)['size'];

            // Read the full packet
            $packet_data = fread($this->socket, $size);
            if (strlen($packet_data) !== $size) {
                break;
            }

            $packet = unpack('V1id/V1type/a*body', $packet_data);

            // Store ID/type once (they should match across packets)
            if ($packetId === null) $packetId = $packet['id'];
            if ($packetType === null) $packetType = $packet['type'];

            $response .= rtrim($packet['body'], "\x00");

            // If less than 4096, it's likely the last packet
            if ($size < 4096) {
                break;
            }
        }

        return [
            'id' => $packetId ?? 0,
            'type' => $packetType ?? 0,
            'body' => $response
        ];
    }
}
