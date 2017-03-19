include_directories(src)
add_executable( hsmutil 
				hsm.c 
				hsm_protocol.c 
				hsm_socket.c
				hsm_tool.c
			)