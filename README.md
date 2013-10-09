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

## Functions

	$ bool isWs(void);

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

