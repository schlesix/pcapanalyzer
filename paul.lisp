;; - This short program opens a pcap file and extracts some informations from each frame.
;; - It ist written in Common LISP.
;; - The program uses the "plokami" module to extract Ethernet frames from the pcap.
;;

(ql:quickload "plokami")
(Use-package :plokami)
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
					; (let ((octets nil)(zahl 0))
  (let ((file (open #P"/Users/thomas/Documents/Development/pcapanalyzer/test.csv" :direction :output
										  :if-exists :append
										  :if-does-not-exist :create)))
    (write-line "TimeIndexSec;TimeIndexUsec;CaptureLength;Length;DstMAC;SrcMAC;FrameType;IpVer;IpIHL;IpTOS;IpLen;IpId;IpOffset;IpTTL;IpL4Proto;IpChkSum;IpSrc;IpDst;TcpSrcPort;TcpDstPort;TcpSeqNo;TcpAckNo;TcpOffset;TcpResv;TcpFlags;TcpWnd;TcpChkSum;TcpUrgPtr" file)

    (with-pcap-reader (reader "/Users/thomas/Documents/Development/pcapanalyzer/test.pcapng" :snaplen 1500)
      "Read Frames from the file test.pcapng an extract L2 and L3 informations. "
      ;; Loop through all Frames in the pcap file
      (capture reader -1
               (lambda (sec usec caplen len buffer)
		 (let ((zeile nil)(zahl 0)(dst_mac "") (src_mac "") )
		   ;; 'buffer' contains the current frame.
		   ;; 
		   ;; Extract time and length informations
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
					       (int2hex (aref buffer 5))))
		      ;; Source MAC address
		      (src_mac  (concatenate 'string
					     (int2hex (aref buffer 6)) ":"
					     (int2hex (aref buffer 7)) ":"
					     (int2hex (aref buffer 8)) ":"
					     (int2hex (aref buffer 9)) ":"
					     (int2hex (aref buffer 10)) ":"
					     (int2hex (aref buffer 11)) ))
		   (setq zeile (concatenate 'string zeile ";" dst_mac ";" src_mac))
		   (write-line zeile file)
		   ))))
    (close file)))

