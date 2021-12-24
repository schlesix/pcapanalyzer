(ql:quickload "plokami")
(use-package :plokami)
;;(find-all-devs)

(defun int2hex (wert)
  ;; hexstr ist der hexadezimale Rückgabewert
  (let* ((hexstr (write-to-string wert :base 16)   )
	 ;; Hexadezimalzahl ggfs. auf zwei Stellen erweitern	 
	 (l (length hexstr) ))
    (if (= 1 l)
        (setq hexstr  (concatenate 'string "0" hexstr)))
    hexstr
    ))

(with-pcap-reader (reader "test.pcapng" :snaplen 1500)
  (capture reader -1
           (lambda (sec usec caplen len buffer)
	     ;; Zeit- und Längendaten für jedes Paket ausgeben
	     (princ ">")
	     (terpri)
	     (princ "Zeitindex: ")
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
	     ;; Deklaration von Variablen
	     ;; Direkte Zuweisung, sofern möglich
	     (let* ((dst_mac  (concatenate 'string
					 (int2hex (aref buffer 0)) ":"
					 (int2hex (aref buffer 1)) ":"
					 (int2hex (aref buffer 2)) ":"
					 (int2hex (aref buffer 3)) ":"
					 (int2hex (aref buffer 4)) ":"
					 (int2hex (aref buffer 5)) ":"))
	     (src_mac  (concatenate 'string
					 (int2hex (aref buffer 6)) ":"
					 (int2hex (aref buffer 7)) ":"
					 (int2hex (aref buffer 8)) ":"
					 (int2hex (aref buffer 9)) ":"
					 (int2hex (aref buffer 10)) ":"
					 (int2hex (aref buffer 11)) ":"))
	     ( frame_type  (concatenate 'string
					    (int2hex (aref buffer 12)) (int2hex (aref buffer 13))))
		    (ip_ver"")
		    (ihl 0)
		    (tos "")
		    (ip_len "")
		    (ip_id "")
		    (ip_off "")
		    (ip_ttl "")
		    (ip_p "")
		    (ip_sum "")
		    (ip_src "")
		    (ip_dst "")
		    (tcp_src "")
		    (tcp_dst "")
		    (tcp_seq "")
		    (tcp_ack "")
		    (tcp_off "")
		    (tcp_rsv "")
		    (tcp_flg "")
		    (tcp_wnd "")
		    (tcp_chk "")
		    (tcp_urg "")
		    )
	     (setq ip_ver (int2hex (floor (aref buffer 14) 16)))
	     (setq ihl (* (mod (aref buffer 14) 16) 32))
	     (setq tos (int2hex(aref buffer 15)))
	     (setq ip_len  (concatenate 'string
					    (int2hex (aref buffer 16)) (int2hex (aref buffer 17))))
	     (setq ip_id  (concatenate 'string
					    (int2hex (aref buffer 18)) (int2hex (aref buffer 19))))
	     (setq ip_off  (concatenate 'string
					    (int2hex (aref buffer 20)) (int2hex (aref buffer 21))))
	     (setq ip_ttl (int2hex (aref buffer 22)))
	     (setq ip_p (int2hex (aref buffer 23)))
	     (setq ip_sum  (concatenate 'string
					    (int2hex (aref buffer 24)) (int2hex (aref buffer 25))))
	     (setq ip_src  (concatenate 'string
					    (write-to-string (aref buffer 26)) "." (write-to-string (aref buffer 27)) "." (write-to-string (aref buffer 28)) "."  (write-to-string (aref buffer 29))))
	     (setq ip_dst  (concatenate 'string
					(write-to-string (aref buffer 30)) "." (write-to-string (aref buffer 31)) "." (write-to-string (aref buffer 32)) "."  (write-to-string (aref buffer 33))))
	     (setq tcp_src  (concatenate 'string
					    (int2hex (aref buffer 34)) (int2hex (aref buffer 35))))
	     (setq tcp_dst  (concatenate 'string
					    (int2hex (aref buffer 36)) (int2hex (aref buffer 37))))
	     (setq tcp_seq  (concatenate 'string
					    (int2hex (aref buffer 38)) (int2hex (aref buffer 39))
					    (int2hex (aref buffer 40)) (int2hex (aref buffer 41)) ))
	     (setq tcp_ack  (concatenate 'string
					    (int2hex (aref buffer 42)) (int2hex (aref buffer 43))
					    (int2hex (aref buffer 44)) (int2hex (aref buffer 45)) ))
	     (setq tcp_off (int2hex (floor (aref buffer 46) 16)))
	     (setq tcp_rsv (int2hex (* (mod (aref buffer 46) 16) 32)))
	     (setq tcp_flg  (concatenate 'string
					    (int2hex (aref buffer 47)) (int2hex (aref buffer 48))))
	     (setq tcp_flg (int2hex (aref buffer 47)))
	     (setq tcp_wnd  (concatenate 'string
					    (int2hex (aref buffer 48)) (int2hex (aref buffer 49))))
	     (setq tcp_chk  (concatenate 'string
					    (int2hex (aref buffer 50)) (int2hex (aref buffer 51))))
	     (setq tcp_urg  (concatenate 'string
					    (int2hex (aref buffer 52)) (int2hex (aref buffer 53))))
	     
	     (princ (concatenate  'string "*" src_mac " => " dst_mac " FT: " frame_type " IPv: " ip_ver " IHL: " (write-to-string ihl) " TOS: " tos " IPLEN: " ip_len " IPID: " ip_id " IPOFF: " ip_off " IPTTL: " ip_ttl " IPP: " ip_p " IPSUM: " ip_sum " IPSRC: " ip_src ":" tcp_src " IPDST: " ip_dst ":" tcp_dst " tcp_seq: " tcp_seq " tcp_ack: " tcp_ack " TCPOFF: " tcp_off " TCPRSV: " tcp_rsv " TCPFLG: " tcp_flg " TCPWND: " tcp_wnd " TCPCHK: " tcp_chk " TCPURG: " tcp_urg))
	       (terpri)
	       )
	     )))
