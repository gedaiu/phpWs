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

#### Properties
	
	
	
#### Methods

	$ __construct()
	Create the object and set the default values

	$ string __toString()
	Return the payloadData and if a mask is present the data will be decoded

	$ long push(string)
	Push data in the WsFrame
	
	if	
	currentSize == -3 the FIN, RSV, opcode, payloadLength and haveMask will be filled
	currentSize == -2 the payloadData will be set if the extended length bytes are present
	currentSize == -1 the mask will be filled if masking bytes are present
	currentSize >= 0 the payload data will be filled until it's full
	
	$ string encode()
	Return the raw frame data	

	$ bool isReady()
	Return true if the frame the payload data is full (payloadLength == currentLength)


	$ void reset()
	Prepare the WsFrame to receive a new frame, empty payloadData and set all the properties to the default values.

## Functions

	$ bool is_ws(void);

Check if the current conection is a websocket connection

	$ void ws_handshake(void);

Initiate the handshake with the client

	$ void ws_send(string message);

Send a text message to the client

	$ bool/string ws_receive(void);

Receive data from the client. This action is non-blocking and you should use a sleep function to avoid high CPU loadings.
	
	return false: there is no message

	return string: the returned string is the client message


## Example


Sending messages

		<?php
			
		if(is_ws()) {
			ws_handshake();
			
			for($i=0; $i<2; $i++) {
				ws_send("Hello World $i!");
			}

		} else {
			echo "This works only with ws protocol\n";
		}


Receive messages

		<?php
		if(is_ws()) {
			ws_handshake();

			while(1) {
				$r = ws_receive();
				
				if($r !== false) {
					//$r is the message from the client
				}

				usleep(2000);
			}
		} else {
			echo "This works only with ws protocol\n";
		}


## About the author

Szabo Bogdan
szabobogdan@yahoo.com

