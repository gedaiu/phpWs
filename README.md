# Web Sockets for PHP  (phpWs)

This is a websocket extension for the php5 language. This extension extends the apache2handler to 
accept websocket connections.

This is an experimental implementation and supports protocol versions 7, 8, and 13 of the WebSocket protocol.


## Requirements

Php5
Apache2.x
Apache2handler

## How to install

	$ phpize
	$ ./configure
	$ make
	$ make install

## Classes

### class WsFrame

This class is an abstractisation of a websocket frame

#### Properties
	
##### payload properties

	public int currentLength = -3
		The current payload length.
			if = -3 the push() method will try to fill the frame header
			if = -2 the push() method will try to fill the payloadLength
			if = -1 the push() method will try to fill the frame mask
			if >= 0 the push() method will try to fill the payloadData

	public int payloadLength = 0
		The desired payload length

	public string payloadData = ""
		The current payload which is allways unmasked and allways will have $payloadLength length. The unused chars will be filled with '-'

#### frame header
	public bool FIN = true
		The FINalisation flag
		
	public bool RSV1 = false
		Plugin flag
		
	public bool RSV2 = false
		Plugin flag
		
	public bool RSV3 = false
		Plugin flag
		
	public int opcode = 1
		The opcode 1 = text, 2 = binary, 3-7 = reserved for further non-control frames, 8 = close, 9 = ping, 10 = pong

#### masking data
	public bool haveMask = false
		Tell if the payload should be masked or not
		
	public string mask = "****"
		The masking string. It must have 4 characters. The server should never mask the payload when it send frames to the client.
		
	
#### Methods

	$ public __construct()
		Create the object and set the default values

	$ public string __toString()
		Return the payloadData and if a mask is present the data will be decoded

	$ public long push(string)
		Push data in the WsFrame
	
		if	
			currentSize == -3 the FIN, RSV, opcode, payloadLength and haveMask will be filled
			currentSize == -2 the payloadData will be set if the extended length bytes are present
			currentSize == -1 the mask will be filled if masking bytes are present
			currentSize >= 0 the payload data will be filled until it's full
	
	$ public string encode()
		Return the raw frame data	

	$ public bool isReady()
		Return true if the frame the payload data is full (payloadLength == currentLength)


	$ public void reset()
		Prepare the WsFrame to receive a new frame, empty payloadData and set all the properties to the default values.


### class WsServer

This class handles the connection with the client. 

#### Properties

	public bool readInBlockingMode = false
		Tell to the WsServer how to read data from the client
			true = the program will be blocked until data is available to read
			false = the program will not be blocked

	public int readInterval = 1000 (microseconds)
		The amount of microseconds that the WsServer will wait between reeading actions in non-blocking mode
	
	public bool serving = false
		Tell the current status of the server

	public WsFrame readFrame
		The WsFrame that is used to read data from the client
	
	public string readBuffer = ""
		The read buffer

##### callbacks
	protected void function(WsFrame $frame) _onMessage
		callback when a frame was received
		
	protected bool function() _beforeRead
		callback before the server start to read data from client.
		
		the callback must return a boolean. 
			if TRUE is returned the server will read data from the client
			if FALSE is returned the server will not read data from the client, but the buffer processing phase will not be ignored 
		
	
	protected void function(string $data) _afterRead
		callback after the read was made. The first argument is the binary data read from the client
	
	protected bool function() _beforeProcess
		callback before the server start to process the read buffer
		
		the callback must return a boolean. 
			if TRUE is returned the server will process the the read buffer
			if FALSE is returned the server will not process the read buffer
		
	protected void function(WsFrame $frame)  _afterProcess
		callback after the processing was made. The first argument is the reading frame
		
#### Methods

	$ public __construct()
		Create the object and set the default values
		
	$ public string receive()
		Receive data from the client. 
		Return the raw received data	
		
		
	$ public bool processRawData(string $data)
		Adds $data to the readingBuffer and push it to the readFrame

	$ public void serve()
		Start to serving the client

	$ private callback(string $method, $arg1, ...);
		Call the $method with the arguments
	
	$ public void function(WsFrame $frame) onMessage
		Trigger the onMessage event
		
	$ public bool function() beforeRead
		Trigger the beforeRead event
		
	$ public void function(string $data) afterRead
		Trigger the afterRead event
	
	$ public bool function() beforeProcess
		Trigger the beforeProcess event
		
	$ public void function(WsFrame $frame)  afterProcess
		Trigger the afterProcess event

	$ public void function(function $callback) setBeforeRead
		Set the beforeRead callback
		
	$ public void function(function $callback) setAfterRead
		Set the afterRead callback

	$ public void function(function $callback) setBeforeProcess
		Set the beforeProcess callback

	$ public void function(function $callback) setAfterProcess
		Set the afterProcess callback
	
	$ public void function(function $callback) setOnMessage
		Set the onMessage callback
	

## Functions

	$ bool is_ws(void);
		Check if the current conection is a websocket connection

	$ void ws_handshake(void);
		Initiate the handshake with the client

	$ void ws_send(string/WsFrame $message);
		if $message is string, sends a text message to the client
		if $message is a WsFrame, sends the encoded WsFrame 

## Example


This is an example of an echo server, that send back the first 10 messages

	<?php

	$server = new WsServer();
	$server->readInBlockingMode = false;
	$server->readInterval = 100000;


	$msgCnt = 0;

	$server->setOnMessage(function ($frame) {
		global $msgCnt, $server;
	
		$msgCnt++;
		ws_send($frame);
	
	
		if($msgCnt == 10) {
			$server->serving = false;
		}
	});


	$server->serve();
	
	
	ws_close();

## About the author

Szabo Bogdan
szabobogdan@yahoo.com

