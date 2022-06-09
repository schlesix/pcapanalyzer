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
(write-line "TimeIndexSec;TimeIndexUsec;CaptureLength;Length;DstMAC;SrcMAC;FrameType;IpVer;IpIHL;IpTOS;IpLen;IpId;IpOffset;IpTTL;IpL4Proto;IpChkSum;IpSrc;IpDst;TcpSrcPort;TcpDstPort;TcpSeqNo;TcpAckNo;TcpOffset;TcpResv;TcpFlags;TcpWnd;TcpChkSum;TcpUrgPtr" file)

    (plokami:with-pcap-reader (reader "/Users/thomas/Documents/Development/pcapanalyzer/test.pcapng" :snaplen 1500)

      (plokami:capture reader -1
               (lambda (sec usec caplen len buffer)
		 (let ((zeile nil)(zahl 0)(dst_mac "")(src_mac "") (ip_ver "") (ip_ihl "") (ip_len "") (ip_id "") (ip_off "") (ip_ttl "") (ip_p "") (ip_sum "") (ip_src "") (ip_dst "") (tcp_src "") (tcp_dst "") (tcp_seq "") (tcp_ack "") (tcp_off "") (tcp_rsv "") (tcp_flg "") (tcp_wnd "") (tcp_chk "") (tcp_urg "")  )

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
		      (setq tos "")
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

		 (setq ip_ver (int2hex (floor (aref buffer 14) 16)))
		 ;; Ipv4 Initial header length
		 (setq ihl (* (mod (aref buffer 14) 16) 32))
		 ;; IPv4 Type of Service
		 (setq tos (int2hex(aref buffer 15)))
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

		   
		   (setq zeile (concatenate 'string zeile ";" ip_ver ";" ip_ihl))

		   
		   (write-line zeile file)		   
		   
		   ))) ; plokami:capture reader

      
      ) ; plokami:with-pcap-reader
  
		   
 (close file))) ; let file open...

