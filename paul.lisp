;; - This short program opens a pcap file and extracts some informations from each frame.
;; - It ist written in Common LISP.
;; - The program uses the "plokami" module to extract Ethernet frames from the pcap.
;;

;(ql:quickload "plokami")
;(Use-package :plokami)
;;(find-all-devs)

(defun int2hex (int_value)
  "Convert a decimal value into a hexadecimal value. Currently only for Bytes (0-255)"
  ;; hexstr ist der hexadezimale Rückgabewert
  (let* ((hexstr (write-to-string int_value :base 16)   )
	 ;; Hexadezimalzahl ggfs. auf zwei Stellen erweitern	 
	 (l (length hexstr) ))
    (if (= 1 l)
        (setq hexstr  (concatenate 'string "0" hexstr)))
    hexstr
    ))


(defun pcap-einlesen ()
      "Read Frames from the file test.pcapng an extract L2 and L3 informations. "


(let ((file (open #P"/Users/thomas/Documents/Development/pcapanalyzer/test.csv" :direction :output
										  :if-exists :append
										  :if-does-not-exist :create)))
(write-line "TimeIndexSec;TimeIndexUsec;CaptureLength;Length;DstMAC;SrcMAC;FrameType;IpVer;IpIHL;IpTOS;IpLen;IpId;IpOffset;IpTTL;IpL4Proto;IpChkSum;IpSrc;IpDst;TcpSrcPort;TcpDstPort;TcpSeqNo;TcpAckNo;TcpOffset;TcpResv;TcpFlags;TcpWnd;TcpChkSum;TcpUrgPtr;PayloadHash" file)

    (plokami:with-pcap-reader (reader "/Users/thomas/Documents/Development/pcapanalyzer/test.pcapng" :snaplen 1500)

      (plokami:capture reader -1
               (lambda (sec usec caplen len buffer)
		 (let ((zeile nil) (zahl 0)(dst_mac "")(src_mac "") (frame_type "") (ip_ver "") (ip_ihl "") (ip_tos "")  (ip_len "") (ip_id "") (ip_off "") (ip_ttl "") (ip_p "") (ip_sum "") (ip_src "") (ip_dst "") (tcp_src "") (tcp_dst "") (tcp_seq "") (tcp_ack "") (tcp_off "") (tcp_rsv "") (tcp_flg "") (tcp_wnd "") (tcp_chk "") (tcp_urg "") (payloadhash "")) 

		   (setq zeile "")
		   (princ ">")
		   (terpri)
		   (princ "Time index: ")
		   (princ sec)
		   (princ ".")
		   (princ usec)
		   (terpri)
		   (princ "Capture Length: ")
		   (princ caplen)
		   (terpri)
		   (princ "Length: ")
		   (princ len)
		   (terpri)
		   (setq zeile (concatenate 'string zeile (write-to-string sec ) ";" (write-to-string usec) ";" (write-to-string caplen) ";"  (write-to-string len)))
					;	  (write-to-string usec) ";" (write-to-string(caplen)) ";" ))
					;(print zeile)
		   ;; Destination MAC address
		   (setq dst_mac  (concatenate 'string
					       (int2hex (aref buffer 0)) ":"
					       (int2hex (aref buffer 1)) ":"
					       (int2hex (aref buffer 2)) ":"
					       (int2hex (aref buffer 3)) ":"
					       (int2hex (aref buffer 4)) ":"
					       (int2hex (aref buffer 5)))) ; setq dst_mac

		      ;; Source MAC address
		      (setq src_mac  (concatenate 'string
					     (int2hex (aref buffer 6)) ":"
					     (int2hex (aref buffer 7)) ":"
					     (int2hex (aref buffer 8)) ":"
					     (int2hex (aref buffer 9)) ":"
					     (int2hex (aref buffer 10)) ":"
					     (int2hex (aref buffer 11)) ))	; setq src_mac	   

		   (setq zeile (concatenate 'string zeile ";" dst_mac ";" src_mac))

		      ;; Frame type
		      (setq frame_type  (concatenate 'string
						 (int2hex (aref buffer 12)) (int2hex (aref buffer 13))))
		      ;; Declare variables for L3/L4
		      (setq ip_ver"")
		      (setq ip_ihl "")
		      (setq ip_tos "")
		      (setq ip_len "")
		      (setq ip_id "")
		      (setq ip_off "")
		      (setq ip_ttl "")
		      (setq ip_p "")
		      (setq ip_sum "")
		      (setq ip_src "")
		      (setq ip_dst "")
		      (setq tcp_src "")
		      (setq tcp_dst "")
		      (setq tcp_seq "")
		      (setq tcp_ack "")
		      (setq tcp_off "")
		      (setq tcp_rsv "")
		      (setq tcp_flg "")
		      (setq tcp_wnd "")
		      (setq tcp_chk "")
		      (setq tcp_urg "")
		   		     ; (setq tcp_urg (map 'string #'code-char (md5:md5sum-sequence (subseq buffer 21 caplen))))
		   (setq tcp_urg  (md5:md5sum-sequence (subseq buffer 21 caplen)))
		   		   ;(loop for elem across tcp_urg do (print  (int2hex  elem)     ))
		   		   (loop for elem across tcp_urg do (setq payloadhash (concatenate 'string payloadhash (int2hex  elem)     )))

		;       (Print "->")

		;			(princ payloadhash)
		  ; (print  (write-to-string (subseq buffer 21 caplen)))

		 ;  (print (write-to-string tcp_urg))
		 ;  (Print (write-to-string (sxhash (aref buffer ))))
		; (print "<-")
		 (setq ip_ver (int2hex (floor (aref buffer 14) 16)))
		 ;; Ipv4 Initial header length
		 (setq ip_ihl (int2hex (* (mod (aref buffer 14) 16) 4)))
		 ;; IPv4 Type of Service
		 (setq ip_tos (int2hex(aref buffer 15)))
		 ;; IPv4 length
		 (setq ip_len  (concatenate 'string
					    (int2hex (aref buffer 16)) (int2hex (aref buffer 17))))
		 ;; IPv4 identification
		 (setq ip_id  (concatenate 'string
					   (int2hex (aref buffer 18)) (int2hex (aref buffer 19))))
		 ;; IPv4 offset
		 (setq ip_off  (concatenate 'string
					    (int2hex (aref buffer 20)) (int2hex (aref buffer 21))))
		 ;; IPv4 time-to-live
		 (setq ip_ttl (int2hex (aref buffer 22)))

		   
		   (setq zeile (concatenate 'string zeile ";" frame_type  ";" ip_ver ";" ip_ihl ";" ip_tos ";" ip_len ";" ip_id ";" ip_off ";" ip_ttl))

 (setq ip_p (int2hex (aref buffer 23)))
		 ;; IPv4 Header checksum
		 (setq ip_sum  (concatenate 'string
					    (int2hex (aref buffer 24)) (int2hex (aref buffer 25))))
		 ;; IPv4 source address
		 (setq ip_src  (concatenate 'string
					    (write-to-string (aref buffer 26)) "." (write-to-string (aref buffer 27)) "." (write-to-string (aref buffer 28)) "."  (write-to-string (aref buffer 29))))
		 ;; IPv4 destination address
		 (setq ip_dst  (concatenate 'string
					    (write-to-string (aref buffer 30)) "." (write-to-string (aref buffer 31)) "." (write-to-string (aref buffer 32)) "."  (write-to-string (aref buffer 33))))
		 ;; TCP source port
		 (setq tcp_src  (concatenate 'string
					     (int2hex (aref buffer 34)) (int2hex (aref buffer 35))))
		 ;; TCP destination port
		 (setq tcp_dst  (concatenate 'string
					     (int2hex (aref buffer 36)) (int2hex (aref buffer 37))))
		 ;; TCP sequence number
		 (setq tcp_seq  (concatenate 'string
					     (int2hex (aref buffer 38)) (int2hex (aref buffer 39))
					     (int2hex (aref buffer 40)) (int2hex (aref buffer 41)) ))
		 ;; TCP acknowledge number
		 (setq tcp_ack  (concatenate 'string
					     (int2hex (aref buffer 42)) (int2hex (aref buffer 43))
					     (int2hex (aref buffer 44)) (int2hex (aref buffer 45)) ))

		   (setq zeile (concatenate 'string zeile ";" ip_p ";" ip_sum ";" ip_src ";" ip_dst ";" tcp_src ";" tcp_dst ";" tcp_seq ";" tcp_ack))

		 ;; Tcp offset
		 (setq tcp_off (int2hex (floor (aref buffer 46) 16)))
		 ;; TCP reserved
		 (setq tcp_rsv (int2hex (* (mod (aref buffer 46) 16) 32)))
		 ;; TCP flags
		 (setq tcp_flg (int2hex (aref buffer 47)))
		 ;; TCP window size
		 (setq tcp_wnd  (concatenate 'string
					     (int2hex (aref buffer 48)) (int2hex (aref buffer 49))))
		 ;; TCP checksum
		 (setq tcp_chk  (concatenate 'string
					     (int2hex (aref buffer 50)) (int2hex (aref buffer 51))))
		 ;; TCP urgent pointer
		 (setq tcp_urg  (concatenate 'string
					     (int2hex (aref buffer 52)) (int2hex (aref buffer 53))))		   

		   (setq zeile (concatenate 'string zeile ";" tcp_off ";" tcp_rsv ";" tcp_flg ";" tcp_wnd ";" tcp_chk ";" tcp_urg ";" payloadhash))

		   
		   (write-line zeile file)		   
		   
		   ))) ; plokami:capture reader

      
      ) ; plokami:with-pcap-reader
  
		   
 (close file))) ; let file open...

