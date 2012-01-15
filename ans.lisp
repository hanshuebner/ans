;; -*- mode: common-lisp -*-
;;
;; Copyright (C) 2001 Franz Inc, Berkeley, CA.  All rights reserved.
;;
;; This code is free software; you can redistribute it and/or
;; modify it under the terms of the version 2.1 of
;; the GNU Lesser General Public License as published by 
;; the Free Software Foundation, as clarified by the Franz
;; preamble to the LGPL found in
;; http://opensource.franz.com/preamble.html.
;;
;; This code is distributed in the hope that it will be useful,
;; but without any warranty; without even the implied warranty of
;; merchantability or fitness for a particular purpose.  See the GNU
;; Lesser General Public License for more details.
;;
;; Version 2.1 of the GNU Lesser General Public License can be
;; found at http://opensource.franz.com/license.html.
;; If it is not present, you can access it from
;; http://www.gnu.org/copyleft/lesser.txt (until superseded by a newer
;; version) or write to the Free Software Foundation, Inc., 59 Temple
;; Place, Suite 330, Boston, MA  02111-1307  USA
;;
;; $Id: ans.cl,v 1.21 2002/02/21 19:28:29 dancy Exp $

(in-package :user)

(use-package :mp)
(use-package :acl-compat.mp)
(use-package :acl-compat.excl)

;; for debugging
(eval-when (compile load eval)
  (proclaim '(optimize (safety 1) (space 1) (speed 1) (debug 3))))

(defmacro while (test &rest body)
  "Repeat body while test is true."
  (list* 'loop
         (list 'unless test '(return nil))
         body))

;; database format
;; a domain name is a list (toplevel secondlevel ...)

;; RRs:
;; an A record is a (unsigned-byte 32)
;; an NS record is a domain name
;; a CNAME record a domain name 
;; a SOA record is a list of (mname rname serial refresh retry expire minimum)
;; a PTR record is a domain name
;; an MX record is a list of (priority domainname)
;; an SRV record is a list of (priority weight port target)

;; If we are not the authority for a record, the TTL will be the universal time of when
;; it expires.... so the real time to live will be  (- TTL (get-universal-time))

;;; a leaf node is a struct
;;; slots 
;;;  name -> node name (in regular string form)
;;;  a  -> list of A records
;;;  ns -> list of NS records
;;;  cname -> cname   ;; Multiple CNAMEs are not allowed (same as BIND)
;;;  soa -> soa
;;;  ptr -> ptr
;;;  mx -> list of mx records
;;;  srv -> list of srv records
;;;  authority -> set to 't' if this nameserver is authoritative for this branch
;;;  parent -> parent node

;;; Having a CNAME and an A record (and possibly a bunch of the other types) is not allowed.

;;; a node is a list of a leaf node and a hash table of children (keyed on label)

;; default params

(defparameter *maxquerytimeout* 3) ;; max we'll wait for a response from a nameserver
(defparameter *verbose* nil)
(defparameter *max-depth* 10) ;; cname and glue lookup limits


;; load in any overrides
(eval-when (compile load eval)
  (load "config.cl"))

;; structs

(defstruct (rr (:print-object rr-printer))
  type 
  rrtype ;; rrtype struct for convenience
  name
  class
  ttl ;; If this is a non-authoritative record, then this is WTD (when to die)
  data
  auth ;; this nameserver is authoritative
  fromauth ;; we got this record from a remote authoritative nameserver
  responsetime ;; for A records belonging to nameservers
  negative ;; this is a negative entry
  )

(defun rr-printer (rr stream &key (mff nil))
  (let ((type (rr-type rr))
	(data (rr-data rr))
	(auth (rr-auth rr)))
    (unless mff
      (format stream "<~A " (domain-to-string (rr-name rr))))
    (format stream "~D IN " (if auth (rr-ttl rr) (- (rr-ttl rr) (get-universal-time))))
    (if* (rr-negative rr)
       then
	    (format stream "~A [NegativeCache]" (rr-type rr))
       else
	    (case (rr-type rr)
	      (:a
	       (format stream "A ~A" (number-to-ipaddr-string data))
	       (if (rr-responsetime rr)
		   (format stream "; (rt:~D)" (rr-responsetime rr))))
	      (:ns
	       (format stream "NS ~A" (list-to-string data)))
	      (:cname
	       (format stream "CNAME ~A" (list-to-string data)))
	      (:ptr
	       (format stream "PTR ~A" (list-to-string data)))
	      (:mx
	       (format stream "MX ~D ~A" 
		       (first data) (list-to-string (second data))))
	      (:soa
	       (format stream "SOA ~A ~A ~D ~D ~D ~D ~D" 
		       (domain-to-string (first data)) 
		       (domain-to-string (second data)) (third data) 
		       (fourth data) (fifth data) (sixth data) (seventh data)))
	      (:srv
	       (format stream "SRV ~D ~D ~D ~A" (first data) (second data) 
		       (third data) (domain-to-string (fourth data))))
	      (t
	       (error "rr-printer: type ~S not supported yet" type))))
    (if (rr-auth rr)
	(format stream "; [auth]"))
    (if (rr-fromauth rr)
	(format stream "; [fromauth]"))
    (if mff
	(write-line "" stream)
      (write-string ">" stream))))
    

(defstruct (leaf (:print-object leaf-printer))
  name
  a
  ns
  cname
  soa
  ptr
  mx
  srv
  authority
  parent
  valid
  )

(defun leaf-printer (leaf stream)
  (format stream "#S(leaf :name ~S :a ~S :ns ~S :cname ~S :soa ~S :ptr ~S :mx ~S :srv ~S :authority ~S :valid ~S) "
	  (leaf-name leaf) (leaf-a leaf) (leaf-ns leaf) 
	  (leaf-cname leaf) (leaf-soa leaf) (leaf-ptr leaf) 
	  (leaf-mx leaf) (leaf-srv leaf) (leaf-authority leaf) 
	  (leaf-valid leaf)))

(defmacro leaf-X-writer (slotname)
  (let ((funcname (intern (format nil "~A-~A-~A" 'leaf slotname 'writer)))
	(accessor (intern (format nil "~A-~A" 'leaf slotname))))
    `(defun ,funcname (leaf value)
       (declare 
	(optimize (speed 3)
		  (safety 1))
	(type leaf leaf))
       (setf (,accessor leaf) value))))

(eval-when (eval compile load)
  (leaf-X-writer a)
  (leaf-X-writer ns)
  (leaf-X-writer cname)
  (leaf-X-writer soa)
  (leaf-X-writer ptr)
  (leaf-X-writer mx)
  (leaf-X-writer srv)
  )

(defun soa-serial (rr)
  (third (rr-data rr)))
(defun soa-minimum (rr)
  (seventh (rr-data rr)))


(defstruct msg
  (msgtype :response)
  id
  flags
  qname
  qtype
  qclass
  question  ;; (name type class)
  answer 
  authority 
  additional
  peeraddr
  peerport
  peertype ;; :tcp :udp
  peersocket ;; for tcp
  )

;; the database
(defparameter *db* nil)
(defparameter *dblock* (make-process-lock :name "*db* lock"))

(defmacro with-dblock (&body body)
  `(with-process-lock (*dblock*)
     ,@body))

;; flags
(eval-when (compile load eval)
(defconstant *QR* #x8000)
(defconstant *AA* #x400)
(defconstant *TC* #x200)
(defconstant *RD* #x100)
(defconstant *RA* #x80)
(defconstant *opcodemask* #x7800)
(defconstant *opcodeshift* -11)
(defconstant *rcodemask* #xf)
)

;; opcodes
(eval-when (compile load eval)
(defconstant *opcodeQUERY* 0)
(defconstant *opcodeIQUERY* 1)
(defconstant *opcodeSTATUS* 2)
(defconstant *opcodeNOTIFY* 4)
(defconstant *opcodeUPDATE* 5)
)


;; rcodes
(eval-when (compile eval load)
  (defconstant *rcodeOKAY* 0) 
  (defconstant *rcodeNOERROR* 0)

  ;; unable to decode query
  (defconstant *rcodeFORMATERROR* 1) 
  (defconstant *rcodeFORMERR* 1)

  ;; unable to process request due to problem w/ nameserver.  MY
  ;; personal experience is that this is like a non-authoritative
  ;; version of NAMEERROR
  (defconstant *rcodeSERVERFAILURE* 2)	
  (defconstant *rcodeSERVFAIL* 2)
  
  ;; Meaningful only for responses from an authoritative name server,
  ;; this code signifies that the domain name referenced in the query
  ;; does not exist.
  (defconstant *rcodeNAMEERROR* 3) 
  (defconstant *rcodeNXDOMAIN* 3)
  
  
  ;; The name server does not support the requested kind of query. 
  (defconstant *rcodeNOTIMPLEMENTED* 4)
  (defconstant *rcodeNOTIMP* 4)
  
  ;; The name server refuses to perform the specified operation for
  ;; policy reasons. For example, a name server may not wish to
  ;; provide the information to the particular requester, or a name
  ;; server may not wish to perform a particular operation (e.g., zone
  ;; transfer) for particular data.
  (defconstant *rcodeREFUSED* 5) 
  
  ;; Some name that ought not to exist, does exist.
  (defconstant *rcodeYXDOMAIN* 6) 
  
  ;; Some RRset that ought not to exist, does exist
  (defconstant *rcodeYXRRSET* 7) 
  
  ;; Some RRset that ought to exist, does not exist.
  (defconstant *rcodeNXRRSET* 8) 

  ;; The server is not authoritative for the zone named in the Zone Section.
  (defconstant *rcodeNOTAUTH* 9) 
  
  ;; A name used in the Prerequisite or Update Section is not within
  ;; the zone denoted by the Zone Section
  (defconstant *rcodeNOTZONE* 10) 
  )


;; classes
(defconstant *classIN* 1) ;; the only one we support
(defconstant *classNONE* 254) 

;; types
(eval-when (compile load eval)
(defconstant *typeA* 1)
(defconstant *typeNS* 2)
(defconstant *typeCNAME* 5)
(defconstant *typeSOA* 6)
(defconstant *typePTR* 12)
(defconstant *typeMX* 15)
(defconstant *typeAAAA* 28) ;; not supported
(defconstant *typeSRV* 33)
;; additional query types
(defconstant *typeAXFR* 252) ;; zone transfer
(defconstant *typeANY* 255) ;; request for all records
)

(eval-when (compile load eval)

  (defstruct rrtype
    keyword
    code
    string
    reader
    writer
    method)
  
  (defparameter *rrtype-by-keyword* nil)
  (defparameter *rrtype-by-code* nil)
  (defparameter *rrtype-by-string* nil)
  
  (defparameter *supported-types* '(:a :ns :cname :soa :ptr :mx :srv))
  
  (dolist (ent 
	      '((:a #.*typeA* "A" leaf-a leaf-a-writer :multi)
		(:ns #.*typeNS* "NS" leaf-ns leaf-ns-writer :multi)
		(:cname #.*typeCNAME* "CNAME" leaf-cname leaf-cname-writer :single)
		(:soa #.*typeSOA* "SOA" leaf-soa leaf-soa-writer :single)
		(:ptr #.*typePTR* "PTR" leaf-ptr leaf-ptr-writer :single)
		(:mx #.*typeMX* "MX" leaf-mx leaf-mx-writer :multi)
		(:srv #.*typeSRV* "SRV" leaf-srv leaf-srv-writer :multi)
		(:aaaa #.*typeAAAA* "AAAA" nil nil nil)
		(:axfr #.*typeAXFR* "AXFR" nil nil nil)
		(:any #.*typeANY* "ANY" leaf-any-reader leaf-any-writer :multi)))
    (let ((rrt (make-rrtype
		:keyword (first ent)
		:code (second ent)
		:string (third ent)
		:reader (fourth ent)
		:writer (fifth ent)
		:method (sixth ent))))
      (setf *rrtype-by-keyword*
	(cons (cons (rrtype-keyword rrt) rrt) *rrtype-by-keyword*))
      (setf *rrtype-by-code*
	(cons (cons (rrtype-code rrt) rrt) *rrtype-by-code*))
      (setf *rrtype-by-string*
	(cons (cons (rrtype-string rrt) rrt) *rrtype-by-string*)))))

;; Special 'any' handlers

(defun leaf-any-reader (leaf)
  (let (res)
    (dolist (type *supported-types*)
      (let* ((rrt (keyword-to-rrtype type))
	     (data (funcall (rrtype-reader rrt) leaf)))
	(if data
	    (case (rrtype-method rrt)
	      (:single
	       (push data res))
	      (:multi
	       (setf res (append res data)))
	      (t 
	       (error "Ack! Bogus method!"))))))
    res))
	
(defun leaf-any-writer (leaf rrs)
  (if (notevery #'rr-negative rrs)
      (error "leaf-any-writer doesn't won't work for non-negative RRs!"))
  (error "not done yet"))


;; other constants
(defconstant *maxlabel* 63)

(defconstant *offsetqdcount* 4)
(defconstant *offsetancount* 6)
(defconstant *offsetnscount* 8)
(defconstant *offsetarcount* 10)

;; globals

(defparameter *usocket* nil)
(defparameter *tsocket* nil)

(defparameter *nextttl* 0)
(defparameter *mainprocess* nil)
(defparameter *expireprocess* nil)
(defparameter *minimumttl* 10) ;; in case we get a RR with a ttl of 0.  This is pretty gross.
(defparameter *secondaryprocess* nil)



;; macro section

(defmacro clearflag (flag flags)
  `(setf ,flags (logand ,flags (logxor ,flag #xffff))))

(defmacro setflag (flag flags)
  `(setf ,flags (logior ,flags ,flag)))

(defmacro setrcode (code flags)
  `(setf ,flags (logior (logand #.(logxor #xffff *rcodemask*) ,flags) ,code)))

(defmacro getrcode (flags)
  `(logand ,flags *rcodemask*))

(defmacro getopcode (flags)
  `(ash (logand ,flags *opcodemask*) *opcodeshift*))

(defmacro with-compression ((cstate) &body body)
  `(let ((,cstate (make-hash-table :test #'equalp)))
     ,@body))

(defmacro nonzerop (thing)
  `(not (= 0 ,thing)))

(defmacro showflag (flags code descrip)
  `(if (nonzerop (logand ,flags ,code)) 
       (write-line ,descrip)))

;;; should skip the check for TCP transport
(defmacro sizecheck (buf offset flags)
  `(if (> ,offset 512)
       (progn
	 (if *verbose* (write-line "Setting *TC* flag"))
	 (setflag *TC* ,flags)
	 (put-short ,buf 2 ,flags)
	 (setf ,offset 512))))

(defmacro make-node (name parent)
  `(list (make-leaf :name ,name :parent ,parent) (make-hash-table :test #'equalp)))

;;; for record types that just hold domain names
(defmacro make-record-maker (type)
  (let ((funcname (intern (format nil "~A-~A-~A" 'make type 'record)))
	(typekeyword (intern #+acl type #-acl (symbol-name type) 'keyword)))
    `(defun ,funcname (name class ttl domain auth fromauth)
       (make-rr :type ,typekeyword
		:rrtype (keyword-to-rrtype ,typekeyword)
		:name name
		:class class
		:ttl ttl
		:data (if (stringp domain) (string-to-list domain) domain)
		:auth auth
		:fromauth fromauth))))

(eval-when (compile load eval)
  (make-record-maker ns)
  (make-record-maker cname)
  (make-record-maker ptr)
  )

(defmacro add-or-update-node (nodename node parent)
  `(setf (gethash ,nodename (second ,parent)) ,node))

(defmacro expired-p (rr now)
  `(>= ,now (rr-ttl ,rr)))

;;; end macro section



(defun ensure-sockets ()
  (unless *usocket*
    (setf *usocket* (socket:make-socket :type :datagram 
					:address-family :internet
					:local-host *dnshost*
					:local-port *dnsport*)))
  (unless *tsocket*
    (setf *tsocket* (socket:make-socket :type :stream
					:address-family :internet
					:local-host *dnshost*
					:local-port *dnsport*
					:reuse-address t
					:connect :passive))))

(defun main (&key forever)
  (if *mainprocess* 
      (process-kill *mainprocess*))
  (setf *mainprocess* (process-run-function "Main Loop" #'main-real))

  (if *expireprocess*
      (process-kill *expireprocess*))
  (setf *expireprocess*  (process-run-function "Expire process" #'expire-loop))
  
  (if forever
      (loop
	(sleep 86400)))
  t)

;; For debugging
(defparameter *lasterror* nil)

(defun main-real ()
;;  (setf socket:*print-hostname-in-stream* nil) ;; definitely not good for a nameserver
  (ensure-sockets)
  (ensure-db)
  (dolist (pair *zonelist*)
    (read-zone-file (first pair) (second pair) t))
  (initialize-secondaries)
  (if *secondaryprocess*
      (process-kill *secondaryprocess*))
  (setf *secondaryprocess* (process-run-function "Secondary process" #'secondary-loop))
  
  (let ((readylist)
	(waitlist (list *usocket* *tsocket*)))
    (loop
      (setf readylist (wait-for-input-available waitlist))
      (if (member *usocket* readylist)
	  (multiple-value-bind (buf size peeraddr peerport) 
	      (handler-case (extensions::receive-from *usocket* 512)
		(t (c)
		  (setf *lasterror* c)
		  (format t "Got ~A when doing receive-from.  Ignoring.~%" c)
		  nil))
	    (if buf
		(handler-case (handle-message buf size peeraddr peerport :udp nil)
		  (t (c)
		    (dump-buffer buf size)
		    (format t "Got error ~A (~S) while within handle-message (or below)~%" c c))))
	    (setf readylist (remove *usocket* readylist))))
      (if (member *tsocket* readylist)
	  (process-run-function "TCP client handler" #'tcp-client-handler (socket:accept-connection *tsocket*))))))

    
(defun tcp-client-handler (s)
  (unwind-protect
      (handler-case 
	  (loop
	    (let ((msglen (logior (ash (read-byte s) 8) (read-byte s))))
	      (let ((buf (make-array msglen :element-type '(unsigned-byte 8)))
		    (pos 0))
		(unless (= pos msglen)
		  (setf pos (read-sequence buf s :start pos :end msglen)))
		(handle-message buf msglen (socket:remote-host s) (socket:remote-port s) :tcp s))))
	;; error cases
	(end-of-file () ) ;; not an error
	(t (c)
	  (format t "tcp-client-handler: Stopping due to ~A (~S)~%" c c)))
    ;; cleanup forms
    ;; jkf recommentation.
    (ignore-errors (force-output s))
    (ignore-errors (close s :abort t))))

(defun dump-buffer (buf size)
  (dotimes (i size)
    (if (= (mod i 16) 0)
	(format t "~%~4,'0x: " i))
    (format t "~2,'0x" (aref buf i))
    (if (= (mod i 16) 7)
	(write-string "-")
      (write-string " ")))
  (write-line ""))
      

;; rr type lookups
(defun code-to-rrtype (code)
  (cdr (assoc code *rrtype-by-code* :test #'=)))

(defun keyword-to-rrtype (kw)
  (cdr (assoc kw *rrtype-by-keyword* :test #'eq)))

(defun string-to-rrtype (s)
  (cdr (assoc s *rrtype-by-string* :test #'equalp)))

;;;


(defun extract-questions (buf size msg)
  (let ((offset 12))
    (dotimes (i (get-short buf *offsetqdcount* size))
      (let ((q (make-list 3)))
	(multiple-value-bind (qname newoffset) (get-name buf offset size)
	  (setf offset newoffset)
	  (setf (first q) qname)
	  (setf (second q) (get-short buf offset size))
	  (setf (third q) (get-short buf (+ offset 2) size))
	  (incf offset 4)
	  ;;(format t "question: ~S~%" q)
	  (push q (msg-question msg)))))
    offset))

(defun extract-RR (buf offset size msg section auth fromauth)
  ;;(format t "extract-RR section ~S starting at offset ~D~%" section offset)
  (if (eq section :additional) ;; never treat additional information as fromauth
      (setf fromauth nil))
  (let (type class ttl len rr count status)
    (setf count (get-short buf 
			   (case section
			     (:answer *offsetancount*)
			     (:authority *offsetnscount*)
			     (:additional *offsetarcount*)
			     (t (error "Ack! bogus section specified")))
			   size))
    (dotimes (i count)
      (multiple-value-bind (name newoffset) (get-name buf offset size)
	(setf offset newoffset)
	(setf type (get-short buf offset size))
	(incf offset 2)
	(setf class (get-short buf offset size))
	(incf offset 2)
	(setf ttl (get-long buf offset size))
	(unless auth
	  (if (< ttl *minimumttl*)
	      (setf ttl *minimumttl*))
	  (incf ttl (get-universal-time)))
	(incf offset 4)
	(setf len (get-short buf offset size))
	(incf offset 2)
	(setf status :ok)
	(case type
	  (#.*typeA* 
	   (setf rr (make-a-record name class ttl (get-long buf offset size) auth fromauth))
	   (incf offset 4))
	  (#.*typeNS* 
	   (multiple-value-bind (ns newoffset) (get-name buf offset size)
	     (setf offset newoffset)
	     (setf rr (make-ns-record name class ttl ns auth fromauth))))
	  (#.*typeCNAME*
	   (multiple-value-bind (cname newoffset) (get-name buf offset size)
	     (setf offset newoffset)
	     (setf rr (make-cname-record name class ttl cname auth fromauth))))
	  (#.*typePTR*
	   (multiple-value-bind (ptr newoffset) (get-name buf offset size)
	     (setf offset newoffset)
	     (setf rr (make-ptr-record name class ttl ptr auth fromauth))))
	  (#.*typeMX*
	   (let ((prio (get-short buf offset size)))
	     (incf offset 2)
	     (multiple-value-bind (mx newoffset) (get-name buf offset size)
	       (setf offset newoffset)
	       (setf rr (make-mx-record name class ttl prio mx auth fromauth)))))
	  (#.*typeSOA*
	   (let (info)
	     (multiple-value-bind (mname newoffset) (get-name buf offset size)
	       (setf offset newoffset)
	       (push mname info)
	       (multiple-value-bind (rname newoffset) (get-name buf offset size)
		 (setf offset newoffset)
		 (push rname info)
		 (dotimes (i 5) ;; serial, refresh, retry, expire, minimum
		   (push (get-long buf offset size) info)
		   (incf offset 4))
		 (setf rr (make-soa-record name class ttl (reverse info) auth fromauth))))))
	  (#.*typeSRV* 
	   (let (info)
	     (dotimes (i 3)
	       (push (get-short buf offset size) info)
	       (incf offset 2))
	     (multiple-value-bind (target newoffset) (get-name buf offset size)
	       (setf offset newoffset)
	       (setf rr (make-srv-record name class ttl (third info) (second info) (first info) target auth fromauth)))))
	  (t
	   (format t "extract-RR: Unsupported type ~S~%" type)
	   (incf offset len)
	   (setf status :unsupported)))
	;;(format t "~S -> ~S~%~%~%" name data)
	(if (eq status :ok)
	    (case section
	      (:answer
	       (push rr (msg-answer msg)))
	      (:authority
	       (push rr (msg-authority msg)))
	      (:additional
	       (push rr (msg-additional msg))))))))
  offset)
	   

(defun setup-question (msg)
  (let* ((questions (msg-question msg))
	 (q (first questions)))
    (setf (msg-qname msg) (first q))
    (setf (msg-qtype msg) (second q))
    (setf (msg-qclass msg) (third q))))


(defun make-msg-from-buf (buf size peeraddr peerport peertype peersocket auth)
  (block nil
    (if (< size 12)
	(return (format t "Short packet (~D) received~%" size)))
    (let* ((id (get-short buf 0 size))
	   (flags (get-short buf 2 size))
	   (msg (make-msg :id id
			  :flags flags
			  :peeraddr peeraddr
			  :peerport peerport
			  :peertype peertype
			  :peersocket peersocket
			  ))
	   (offset 12))
      (when (nonzerop (logand *TC* flags)) ;;; XXX - should check for responses from other nameservers and make a TCP request instead
	(format t "This record is truncated.  Not going to bother processing it~%")
	(return (values msg :trunc)))
      (setf offset (extract-questions buf size msg))
      (dolist (section '(:answer :authority :additional))
	(setf offset (extract-RR buf offset size msg section auth (nonzerop (logand *AA* flags)))))
      (setup-question msg)
      (values msg :ok))))

(defun handle-message (buf size peeraddr peerport peertype peersocket)
  (multiple-value-bind (msg status) (make-msg-from-buf buf size peeraddr peerport peertype peersocket nil)
    (if (eq status :ok)
	(case (getopcode (msg-flags msg))
	  (#.*opcodeQUERY*
	   (if (zerop (logand *QR* (msg-flags msg)))
	       (process-run-function "Query handler" #'handle-question msg)
	     (handle-response msg)))
	  (#.*opcodeNOTIFY*
	   (if (zerop (logand *QR* (msg-flags msg)))
	       (process-run-function "Notify request handler" #'handle-notify-request msg)
	     (handle-response msg)))
	  (t
	   (format t "Unimplemented opcode ~D (~S)~%" (getopcode (msg-flags msg)) msg)
	   (send-notimp-response msg))))))

;; easy
(defun send-notimp-response (msg)
  (format t "Sending NOTIMPLEMENTED reponse.~%")
  (setrcode *rcodeNOTIMPLEMENTED* (msg-flags msg))
  (send-msg msg))
  
  

(defconstant *flag-to-descrip* 
    `((#.*QR* . "Query response")
      (#.*AA* . "Authoritative answer")
      (#.*TC* . "Truncated")
      (#.*RD* . "Recursion desired")
      (#.*RA* . "Recursion allowed")))

(defun print-flags (flags)
  (dolist (pair *flag-to-descrip*)
    (showflag flags (the fixnum (car pair)) (cdr pair)))
  (format t "Opcode: ~D~%" (getopcode flags)) 
  (format t "rcode: ~D~%" (getrcode flags)))

;;; utils for reading/building messages.

(defun get-short (buf offset size)
  (if (> (+ 2 offset) size)
      (error "get-short: Ran off end of buffer!"))
  (logior (ash (aref buf offset) 8) (aref buf (1+ offset))))

(defun put-short (buf offset value)
  (setf (aref buf offset) (logand #xff (ash value -8)))
  (setf (aref buf (1+ offset)) (logand #xff value)))

(defun put-long (buf offset value)
  (dotimes (i 4)
    (setf (aref buf (+ (- 3 i) offset)) (logand #xff value))
    (setf value (ash value -8))))

(defun get-long (buf offset size)
  (let ((res 0))
    (if (> (+ 4 offset) size)
	(error "get-long: Ran off end of buffer"))
    (dotimes (i 4)
      (setf res (logior (ash res 8) (aref buf (+ offset i)))))
    res))
    
  

;; question format:  qname, qtype, qclass

;;; qname format: len, characters, <repeat> ,0 
(defun get-name (buf offset size)
  ;;(format t "get-name at offset ~D~%" offset)
  (let (res)
    (loop
      (multiple-value-bind (string newoffset) (get-label buf offset size)
	(cond
	 ((null string)
	  (return (values res newoffset)))
	 ((stringp string)
	  (push string res)
	  (setf offset newoffset))
	 ((listp string)
	  (return (values (append string res) (+ 2 offset))))
	 (t
	  (error "get-name Got unexpected result from get-label!")))))))
	  

(defun put-name-compressor (buf offset name compstate &key nocompress)
  (setf name (reverse name))
    (loop
      (multiple-value-bind (entry found) (gethash name compstate)
	;;(format t "trying to match ~S~%" name)
	(if (and found (null nocompress))
	    (progn
	      ;;(format t "matched at offset ~D~%" entry)
	      (put-short buf offset (logior #b1100000000000000 entry))
	      (return-from put-name-compressor (+ 2 offset))))
	;;(format t "adding ~S -> ~S~%" name offset)
	(if (null nocompress)
	    (setf (gethash name compstate) offset))
	(setf offset (put-label buf offset (pop name)))
	(if (null name)
	    (progn
	      (setf (aref buf offset) 0)
	      (incf offset)
	      (return-from put-name-compressor offset))))))

(defun put-name (buf offset namelist compstate &key nocompress)
  (let ((oldoffset offset))
    (if (stringp namelist)
	(setf namelist (string-to-list namelist)))
    (if (null namelist) 
	(progn
	  (setf (aref buf offset) 0)
	  (incf offset))
      (setf offset (put-name-compressor buf offset namelist compstate :nocompress nocompress)))
    (values offset (- offset oldoffset))))

(defun get-label (buf offset size)
  (if (>= offset size)
      (error "get-label: Ran off the end of the buffer!"))
  (let* ((len (aref buf offset))
	 (string (make-string len)))
    (if (= len 0)
	(values nil (1+ offset))
      (progn 
	;;(format t "get-label: len is ~D~%" len)
	(if (= (logand #b11000000 len) #b11000000) ;; compression
	    (let* ((short (get-short buf offset size))
		   (newoffset (logand #x3fff short)))
	      ;;(format t "get-label: handling compressed name~%")
	      ;;(format t "got short: 0x~x  new offset 0x~x~%" short newoffset)
	      (get-name buf newoffset size))
	  (if (> len *maxlabel*)
	      (error "get-label: *maxlabel* has been exceeded!")
	    (progn
	      (incf offset)
	      (if (> (+ offset len) size)
		  (error "get-label: Ran off the end of the buffer!"))
	      (dotimes (i len)
		(setf (schar string i) (code-char (aref buf (+ offset i)))))
	      (values string (+ offset len)))))))))
  
(defun put-label (buf offset label)
  (let ((len (length label)))
    (if (> len *maxlabel*)
	(error "put-label: Label exceeds max!"))
    (setf (aref buf offset) len)
    (incf offset)
    (dotimes (i len)
      (setf (aref buf (+ offset i)) (char-code (schar label i))))
    (+ offset len)))

;;; never return a TTL smaller than 0
(defun get-adjusted-ttl (rr)
  (max 0 (if (rr-auth rr) (rr-ttl rr) (- (rr-ttl rr) (get-universal-time)))))

(defun put-a-record (buf offset rr cs)
  (setf offset (put-question buf offset (rr-name rr) *typeA* (rr-class rr) cs)) ;; puts NAME, TYPE, CLASS
  ;;; XXX -- this is where the ttl transformation should actually happen.. no earlier
  (put-long buf offset (get-adjusted-ttl rr)) ;; TTL
  (incf offset 4)
  (put-short buf offset 4) ;; RDLENGTH
  (incf offset 2)
  (put-long buf offset (rr-data rr)) ;; RDATA
  (+ offset 4))

(defun put-common-record (buf offset rr cs)
  (setf offset 
    (put-question  ;; NAME, TYPE, CLASS
     buf 
     offset 
     (rr-name rr) 
     (rrtype-code (rr-rrtype rr))
     (rr-class rr) 
     cs)) 
  (put-long buf offset (get-adjusted-ttl rr)) ;; TTL
  (incf offset 4)
  (multiple-value-bind (newoffset size) (put-name buf (+ 2 offset) (rr-data rr) cs) ;; RDATA
    (put-short buf offset size) ;; RDLENGTH
    (setf offset newoffset))
  offset)

(defun put-ns-record (buf offset rr cs)
  (put-common-record buf offset rr cs))

(defun put-cname-record (buf offset rr cs)
  (put-common-record buf offset rr cs))

(defun put-ptr-record (buf offset rr cs)
  (put-common-record buf offset rr cs))

(defun put-mx-record (buf offset rr cs)
  (setf offset (put-question buf offset (rr-name rr) *typeMX* (rr-class rr) cs)) ;; NAME, TYPE, CLASS
  (put-long buf offset (get-adjusted-ttl rr)) ;; TTL
  (incf offset 4)
  (put-short buf (+ offset 2) (first (rr-data rr)))
  (multiple-value-bind (newoffset size) (put-name buf (+ 4 offset) (second (rr-data rr)) cs)
    (put-short buf offset (+ 2 size))
    (setf offset newoffset))
  offset)

(defun put-soa-record (buf offset rr cs)
  (let ((rdlength 0)
	(soa (rr-data rr)))
    (setf offset (put-question buf offset (rr-name rr) *typeSOA* (rr-class rr) cs)) ;; NAME, TYPE, CLASS
    (put-long buf offset (get-adjusted-ttl rr)) ;; TTL
    (incf offset 4)
    (multiple-value-bind (newoffset size) (put-name buf (+ 2 offset) (pop soa) cs)
      (incf rdlength size)
      (multiple-value-bind (newoffset size) (put-name buf newoffset (pop soa) cs)
	(incf rdlength size)
	(dolist (value soa) ;; serial, refresh, retry, expire, minimum
	  (put-long buf newoffset value)
	  (incf rdlength 4)
	  (incf newoffset 4))
	(put-short buf offset rdlength) ;; RDLENGTH
	newoffset))))

;; shouldn't use name compression for the target
(defun put-srv-record (buf offset rr cs)
  (setf offset (put-question buf offset (rr-name rr) *typeSRV* (rr-class rr) cs)) ;; NAME, TYPE, CLASS
  (put-long buf offset (get-adjusted-ttl rr)) ;; TTL
  (incf offset 4) ;; pointing at rdlength now
  (put-short buf (+ offset 2) (first (rr-data rr))) ;; prio
  (put-short buf (+ offset 4) (second (rr-data rr))) ;; weight
  (put-short buf (+ offset 6) (third (rr-data rr))) ;; port  
  (multiple-value-bind (newoffset size) (put-name buf (+ 8 offset) (fourth (rr-data rr)) cs :nocompress t) ;; no compression allowed by the RFC
    (put-short buf offset (+ 6 size))
    (setf offset newoffset))
  offset)
  


(defun put-question (buf offset qname qtype qclass cs) 
  (setf offset (put-name buf offset qname cs))
  (put-short buf offset qtype)
  (put-short buf (+ 2 offset) qclass)
  (+ 4 offset))


;;; We only handle one question.  I think this is pretty typical of
;;; other DNS servers.
(defun handle-question (msg)
  (block nil
    (let* ((rrt (code-to-rrtype (msg-qtype msg)))
	   (keyword (rrtype-keyword rrt)))
      (if (null rrt)
	  (return (format t "Unimplemented query type ~D.  msg is ~S~%" (msg-qtype msg) msg)))
      
      (if* (or (eq keyword :any)
	       (member keyword *supported-types*))
	 then
	      (if *verbose*
		  (format t "~A: ~A? ~A~%" 
			  (socket:ipaddr-to-dotted (msg-peeraddr msg))
			  (rrtype-string rrt)
			  (domain-to-string (msg-qname msg))))
	      
	      (let ((res (resolve (msg-qname msg) rrt)))
		(cond
		 ((and (listp res) (eq (first res) :answers))
		  (setf (msg-answer msg) (second res))
		  (setf (msg-authority msg) (third res))
		  (setf (msg-additional msg) (fourth res))
		  ;;(setflag *AA* (msg-flags msg)) 
		  (send-msg msg))
		 ((and (listp res) (or (eq (first res) :nomatch)
				       (eq (first res) :nxdomain)))
		  (if *verbose* (format t "Answer: ~A~%" (first res)))
		  (setf (msg-answer msg) nil)
		  (setf (msg-additional msg) nil)
		  (setf (msg-authority msg) (third res))
		  (case (first res)
		    (:noname 
		     (setrcode *rcodeNOERROR* (msg-flags msg)))
		    (:nxdomain
		     (setrcode *rcodeNXDOMAIN* (msg-flags msg))))
		  (send-msg msg))
		 ((eq res :servfail)
		  (setrcode *rcodeSERVERFAILURE* (msg-flags msg))
		  (send-msg msg))
		 (t
		  (error "Unexpected return from resolve: ~S" res))))
	      (return t))
      
      (if (eq keyword :axfr)
	  (return (handle-axfr msg)))
      
      (format t "Unimplemented query type ~D.  msg is ~S~%" (msg-qtype msg) msg))))

(excl::defresource sendbuf 
  :constructor #'(lambda () (make-array 65535 :element-type '(unsigned-byte 8))))

(defun send-msg (msg)
  (block nil
    (excl::with-resource (buf sendbuf)
      (let (offset)
	(with-compression (cs)
	  (if (eq :response (msg-msgtype msg))
	      (progn
		(setflag *QR* (msg-flags msg))
		(setflag *RA* (msg-flags msg))))
	  (put-short buf 0 (msg-id msg))
	  (put-short buf 2 (msg-flags msg))
	  (put-short buf *offsetqdcount* 1) ;; we only support one question right now
	  (put-short buf *offsetancount* (length (msg-answer msg)))
	  (put-short buf *offsetnscount* (length (msg-authority msg)))
	  (put-short buf *offsetarcount* (length (msg-additional msg)))
	  (setf offset (put-question buf 12 (msg-qname msg) (msg-qtype msg) (msg-qclass msg) cs))
	  (dolist (func '(msg-answer msg-authority msg-additional))
	    (dolist (rr (reverse (funcall func msg))) 
	      (let ((putfunc (intern (format nil "~A-~A-~A" 'put (rr-type rr) 'record))))
		(setf offset (funcall putfunc buf offset rr cs)))))
	  (if (eq (msg-msgtype msg) :query)  ;; we're sending off a query
	      (progn
		(if (> offset 512)
		    (error "Want to send a query that is larger than 512 bytes.  What the heck!"))
		(if (eq (msg-msgtype msg) :axfr)
		    (ignore-errors 
		     (write-byte (logand #xff (ash offset -8)) (msg-peersocket msg))
		     (write-byte (logand #xff offset) (msg-peersocket msg))
		     (write-sequence buf (msg-peersocket msg) :start 0 :end offset)
		     (return)))
		(ignore-errors (extensions::send-to *usocket* buf offset :remote-host (msg-peeraddr msg) :remote-port (msg-peerport msg)))
		(return)))
	  ;; Responding to a query
	  (if* (and (msg-answer msg) *verbose*)
	     then
		  (write-line "Answer:")
		  (dolist (rr (reverse (msg-answer msg)))
		    (format t "~S~%" rr))
		  (write-line ""))
	  ;; Responding to a query.  Use the same transaction type.
	  ;;(format t "sending a response of type ~S~%" (msg-peertype msg))
	  (if (eq (msg-peertype msg) :udp)
	      (progn
		(sizecheck buf offset (msg-flags msg)) 	    
		(ignore-errors  (extensions::send-to *usocket* buf offset :remote-host (msg-peeraddr msg) :remote-port (msg-peerport msg)))
		(return)))
	;;; tcp
	  (ignore-errors 
	   (write-byte (logand #xff (ash offset -8)) (msg-peersocket msg))
	   (write-byte (logand #xff offset) (msg-peersocket msg))
	   (write-sequence buf (msg-peersocket msg) :start 0 :end offset)
	   (return)))))))


;;; Zone transfer service stuff

;;; XXX -- will need an access control list
;;; a zone transfer response is the SOA.. followed by all the RRs..
;;; followed by the SOA again.   It can be sent in multiple responses
;;; if necessary.
;;; The requested domain must be an exact match for a record that has an
;;; SOA.
(defun handle-axfr (msg)
  (if *verbose*
      (format t "AXFR? ~A~%" (domain-to-string (msg-qname msg))))
  (multiple-value-bind (node exact) (locate-node (msg-qname msg))
    (let ((leaf (first node)))
      (if (and exact (leaf-soa leaf) (leaf-authority leaf))
	  (do-zone-transfer node msg)
	(send-msg msg)))))

(defun do-zone-transfer (node msg)
  (let ((leaf (first node)))
    (push (leaf-soa leaf) (msg-answer msg))
    (add-all-rrs leaf msg)
    (maphash (make-zone-transfer-map-func msg) (second node))
    (push (leaf-soa leaf) (msg-answer msg))
    (send-msg msg)))

		   
(defun make-zone-transfer-map-func (msg)		   
  (lambda (key node)
    (declare (ignore key))
    (let ((leaf (first node)))
      (if (leaf-ns leaf) ;; start of a zone delegation.  Supply ths NS records but don't recurse
	  (dolist (ns (leaf-ns leaf))
	    (push ns (msg-answer msg)))
	;; regular node
	(progn
	  (add-all-rrs leaf msg)
	  (send-msg msg)
	  (setf (msg-answer msg) nil)
	  (maphash (make-zone-transfer-map-func msg) (second node)))))))
	     
(defun add-all-rrs (leaf msg)
  (dolist (reader '(leaf-ns leaf-a leaf-cname leaf-mx leaf-ptr leaf-srv))
    (let ((res (funcall reader leaf)))
      (if res
	  (if (listp res)
	      (dolist (rr res)
		(push rr (msg-answer msg)))
	    (push res (msg-answer msg)))))))
  
;;;; end zone transfer service


;;;;

(defun ensure-db ()
  (unless *db*
    (setf *db* (make-node "" nil))
  (reload-cache)))

(defun reload-cache ()
    (read-zone-file "." *rootcache* nil))

(defun read-zone-file (zone filename auth)
  (declare (ignore zone))
  (ensure-db)
  (with-open-file (s filename)
    (with-dblock
      (let (line tokens (origin ".") (lastname ".") name default-ttl
	    node ttl type typekeyword)
	    (while (setf line (get-next-thing s))
		   (format t "processing: ~S~%" line)
		   (cond
		    ((multiple-value-bind (matched whole inner) (match-regexp "^$TTL\\b+\\(\\B+\\)" line)
		       (declare (ignore whole))
		       (if matched
			   (progn
			     (setf default-ttl (parse-integer inner))
			     (format t "default ttl is ~D~%" default-ttl)
			     t))))
		    ((multiple-value-bind (matched whole inner) (match-regexp "^$ORIGIN\\b+\\(\\B+\\)" line)
		       (declare (ignore whole))
		       (if matched
			   (setf origin inner))))
		    (t
		     (setf tokens (split-regexp "[ 	]+" line))
		     (format t "initial tokens ~S~%" tokens)
		     (if (member (schar line 0) '(#\space #\tab) :test #'char=)
			 (setf name lastname)
		       (progn
			 (setf name (augment-name (pop tokens) origin))
			 (setf lastname name)))
		     (if (string= (first tokens) "")
			 (pop tokens))
		     (format t "remaining tokens ~S~%" tokens)
		     (setf node (ensure-node name auth))
		     ;; Optional TTL
		     (if (match-regexp "^[0-9]+$" (first tokens))
			 (setf ttl (parse-integer (pop tokens)))
		       (setf ttl default-ttl))
		     ;; Optional class
		     (if (string= (first tokens) "IN")
			 (pop tokens))
		     (setf type (pop tokens))
		     (setf typekeyword 
		       (let ((rrt (string-to-rrtype type)))
			 (if (null rrt)
			     (error "Unsupported record type ~S~%" type))
			 (rrtype-keyword rrt)))
		     (add-zone-file-record node *classIN* ttl typekeyword tokens origin))))))))

(defun add-zone-file-record (node class ttl type data origin)
  (let* ((leaf (first node))
	 (auth (leaf-authority leaf))
	 (name (string-to-list (leaf-name leaf))))
    (if (not auth)
	(setf ttl (+ (get-universal-time) ttl)))
    (case type
      (:a (add-or-update-a-record leaf  (make-a-record name class ttl (first data) auth auth)))
      (:ns (add-or-update-ns-record leaf (make-ns-record name class ttl (augment-name (first data) origin) auth auth)))
      (:cname (setf (leaf-cname leaf) (make-cname-record name class ttl (augment-name (first data) origin) auth auth)))
      (:ptr (setf (leaf-ptr leaf) (make-ptr-record name class ttl (augment-name (first data) origin) auth auth)))
      (:soa (setf (leaf-soa leaf) (make-soa-record name class ttl data auth auth)))
      (:mx (add-or-update-mx-record leaf (make-mx-record name class ttl (first data) (augment-name (second data) origin) auth auth)))
      (:srv (add-or-update-srv-record leaf (make-srv-record name class ttl (first data) (second data) (third data) (augment-name (fourth data) origin) auth auth)))
      (t (error "Unsupported type ~A. Data: ~S" type data)))))



(defun get-next-thing (s) 
  (let (line continuing res)
    (while (setf line (read-line s nil nil))
	   ;;(format t "got line: ~S~%" line)
	   ;; remove any comment
	   (let ((semipos (position #\; line)))
	     (when semipos
	       (setf line (subseq line 0 semipos))))
	   (if (not (string= line ""))
	       (if (char= (schar line (1- (length line))) #\()
		   (progn
		     (setf continuing t)
		     (setf res (subseq line 0 (1- (length line)))))
		 (if (not continuing)
		     (return-from get-next-thing line)
		   (if (char= (schar line (1- (length line))) #\))
		       (return-from get-next-thing (concatenate 'string res (subseq line 0 (1- (length line)))))
		     (setf res (concatenate 'string res line)))))))
    nil))
	       
(defun augment-name (name origin)
  (if (not (char= (schar name (1- (length name))) #\.))
      (concatenate 'string name "." origin)
    name))

(defun make-a-record (name class ttl address auth fromauth)
  (if (stringp address)
      (setf address (parse-ip-addr address)))
  (make-rr :type :a
	   :rrtype (keyword-to-rrtype :a)
	   :name name
	   :class class
	   :ttl ttl
	   :data address
	   :auth auth
	   :fromauth fromauth))

(defun make-mx-record (name class ttl prio domain auth fromauth)
  (make-rr :type :mx
	   :rrtype (keyword-to-rrtype :mx)
	   :name name
	   :class class
	   :ttl ttl 
	   :data (list (if (numberp prio) prio (parse-integer prio)) (if (stringp domain) (string-to-list domain) domain))
	   :auth auth
	   :fromauth fromauth))
	   
(defun make-soa-record (name class ttl data auth fromauth)
  (make-rr :type :soa
	   :rrtype (keyword-to-rrtype :soa)
	   :name name
	   :class class
	   :ttl ttl
	   :data (list (if (stringp (first data)) (string-to-list (first data)) (first data))
		       (if (stringp (second data)) (string-to-list (second data)) (second data))
		       (if (stringp (third data)) (parse-integer (third data)) (third data))
		       (if (stringp (fourth data)) (parse-integer (fourth data)) (fourth data))
		       (if (stringp (fifth data)) (parse-integer (fifth data)) (fifth data))
		       (if (stringp (sixth data)) (parse-integer (sixth data)) (sixth data))
		       (if (stringp (seventh data)) (parse-integer (seventh data)) (seventh data)))
	   :auth auth
	   :fromauth fromauth))

(defun make-srv-record (name class tll prio weight port target auth fromauth)
  (make-rr :type :srv
	   :rrtype (keyword-to-rrtype :srv)
	   :name name
	   :class class
	   :ttl tll
	   :data (list (if (stringp prio) (parse-integer prio) prio)
		       (if (stringp weight) (parse-integer weight) weight)
		       (if (stringp port) (parse-integer port) port)
		       (if (stringp target) (string-to-list target) target))
	   :auth auth
	   :fromauth fromauth))

;; Okay if we got the information from an authoritative nameserver
;; or if the information we already have wasn't from an authoritative
;; nameserver.  This relies on the 'AA' flag which is kinda bogus.

;; Perhaps this check should be removed altogether since, I think, these
;; functions are only called nowadays when the in-bailiwick nameserver has
;; been verified already.
(defun should-update-p (rrold rrnew)
  (or (rr-fromauth rrnew) (null (rr-fromauth rrold))))

(defun update-nextttl (rr)
  (if (and (not (rr-auth rr)) (< (rr-ttl rr) *nextttl* ))
      (progn
	;;(format t "lowering *nextttl*.  Waking expire loop~%")
	(setf *nextttl* (rr-ttl rr))
	(wake-expire-loop))))

(defun add-or-update-a-record (leaf rr)
  (let ((spot (member (rr-data rr) (leaf-a leaf) :key #'rr-data :test #'=)))
    (if* spot 
       then
	    (if* (should-update-p (first spot) rr)
	       then
		    (setf (first spot) rr)
		    (update-nextttl rr))
       else
	    (push rr (leaf-a leaf))
	    (update-nextttl rr))))
	      

(defun add-or-update-ns-record (leaf rr)
  (let ((spot (member (rr-data rr) (leaf-ns leaf) :key #'rr-data :test #'equalp)))
    (if* spot
       then
	    (if* (should-update-p (first spot) rr)
	       then
		    (setf (first spot) rr)
		    (update-nextttl rr))
       else
	    (push rr (leaf-ns leaf))
	    (update-nextttl rr))))

;; don't use the priority in comparison
(defun add-or-update-mx-record (leaf rr)
  (let ((spot (member (second (rr-data rr)) (leaf-mx leaf) :key #'(lambda (rr) (second (rr-data rr))) :test #'equalp)))
    (if* spot
       then
	    (if* (should-update-p (first spot) rr)
	       then
		    (setf (first spot) rr)
		    (update-nextttl rr))
       else
	    (push rr (leaf-mx leaf))
	    (update-nextttl rr))))

;;; not really sure how to compare.... for now..   just add.
;;; this will force me to fix other things.
(defun add-or-update-srv-record (leaf rr)
  (push rr (leaf-srv leaf))
  (update-nextttl rr))



(defun domain-to-string (d)
  (if (listp d)
      (list-to-string d)
    (if (string= d "")
	"."
      d)))

(defun list-to-string (list)
  (if (null list)
      "."
    (with-output-to-string (s)
      (dolist (label (reverse list))
	(format s "~A." label))
      s)))

(defun string-to-list (string)
  (if (string= string ".")
      nil
    (reverse (string-to-list-help string 0))))

(defun string-to-list-help (string startpos)
  (if (>= startpos (length string))
      nil
    (let ((dotpos (position #\. string :start startpos)))
      (if (null dotpos)
	  (list (subseq string startpos))
	(cons (subseq string startpos dotpos) (string-to-list-help string (1+ dotpos)))))))



;;; create a node if it doesn't exist
;;; returns the node
(defun ensure-node (namelist auth)
  (with-dblock
    (ensure-db)
    (let (res)
      (if (stringp namelist)
	  (setf namelist (string-to-list namelist)))
      (setf res (ensure-node-help namelist *db*))
      ;;; don't unset the authority setting for a node
      (if auth
	  (setf (leaf-authority (first res)) auth))
      (setf (leaf-valid (first res)) t)
      res)))
  
(defun ensure-node-help (namelist parent)
  (if namelist
      (let ((nodename (first namelist)))
	(multiple-value-bind (node found) (gethash nodename (second parent))
	  (if (not found)
	      (progn
		(setf node (make-node (concatenate 'string nodename "." (leaf-name (first parent))) parent))
		(add-or-update-node nodename node parent)))
	  (ensure-node-help (rest namelist) node)))
    parent))

(defun locate-node (namelist)
  (with-dblock
    (ensure-db)
    (if (stringp namelist)
	(setf namelist (string-to-list namelist)))
    (locate-node-help namelist *db*)))

(defun locate-node-help (namelist parent)
  (block nil
    (if namelist
	(let ((nodename (first namelist)))
	  (multiple-value-bind (node found) (gethash nodename (second parent))
	    (if (not found)
		(return (values (locate-nearest-valid-node parent) nil)))
	    (locate-node-help (rest namelist) node)))
      (values parent t))))

;; Called while holding dblock
(defun locate-nearest-valid-node (node)
  (let ((leaf (first node)))
    (if (not (leaf-valid leaf))
	(locate-nearest-valid-node (leaf-parent leaf))
      node)))

(defun node-p (node)
  (and (listp node) (= 2 (length node)) (eq (type-of (second node)) 'hash-table)))

(defun locate-nearest-nameservers-node (node)
  (with-dblock
    (locate-nearest-nameservers-node-help 
     (if (node-p node) node (locate-node node)))))

(defun locate-nearest-nameservers-node-help (node)
  (if (null node)
      (progn
	(format t "***Reloading root nameservers cache***~%")
	(reload-cache)
	*db*)
    (if (and (leaf-ns (first node))
	     (not (any-rrs-negative-p (leaf-ns (first node)))))
	node
      (locate-nearest-nameservers-node-help (leaf-parent (first node))))))

(defun locate-nearest-soa-node (node)
  (with-dblock
    (locate-nearest-soa-node-help (if (node-p node) node (locate-node node)))))

(defun locate-nearest-soa-node-help (node)
  (if (null node)
      nil
    (if (and (leaf-soa (first node))
	     (not (any-rrs-negative-p (leaf-soa (first node)))))
	node
      (locate-nearest-soa-node-help (leaf-parent (first node))))))

(defun locate-rr (domain reader)
  (with-dblock
      (multiple-value-bind (node exact) (locate-node domain)
	(if exact
	    (funcall reader (first node))))))


;;; Utils

(defun dump-node (node)
  (format t "~A~%"  (first node))
  (maphash #'(lambda (key value)
	       (declare (ignore key))
	       (dump-node value))
	   (second node)))

(defun get-ip-addr-piece (string offset)
  (multiple-value-bind (value newoffset) (parse-integer string :start offset :junk-allowed t)
    (if (or (< value 0) 
	    (> value 255)
	    (and (not (= newoffset (length string)))
		 (not (char= (schar string newoffset) #\.))))
	(error "Bogus IP address!"))
    (values value (1+ newoffset))))
    
(defun parse-ip-addr (string)
  (let ((offset 0)
	(res 0))
    (dotimes (i 4)
      (multiple-value-bind (value newoffset) (get-ip-addr-piece string offset)
	(setf res (logior (ash res 8) value))
	(setf offset newoffset)))
    res))

(defun number-to-ipaddr-string (number)
  (let ((shift -24))
    (with-output-to-string (s)
      (dotimes (i 4)
	(format s "~d" (logand #xff (ash number shift)))
	(incf shift 8)
	(if (not (= i 3))
	    (write-string "." s)))
      s)))

;;;
;;; Expiration stuff
;;;

(defun remove-expired (list now)
  (let (res)
    (dolist (rr list)
      (if (not (expired-p rr now))
	  (progn
	    (if (< (rr-ttl rr) *nextttl*)
		(setf *nextttl* (rr-ttl rr)))
	    (push rr res))))
    res))


(defun expire-records (now &optional (node *db*))
  (declare 
   (optimize (speed 3)
	    (safety 1)))
  (with-dblock
    ;; first the node
    (let ((leaf (the leaf (first node))))
      (if* (not (leaf-authority leaf)) ;; don't attempt to expire authoritative records
	 then
	      (dolist (type *supported-types*)
		(let* ((rrt (keyword-to-rrtype type))
		       (reader (rrtype-reader rrt))
		       (writer (rrtype-writer rrt))
		       (rrs (funcall reader leaf)))
		  (cond
		   ((eq (rrtype-method rrt) :multi)
		    (funcall writer leaf (remove-expired rrs now)))
		   ((eq (rrtype-method rrt) :single)
		    (if rrs
			(if (expired-p rrs now)
			    (funcall writer leaf nil)
			  (if (< (rr-ttl rrs) *nextttl*)
			      (setf *nextttl* (rr-ttl rrs))))))
		   (t
		    (error "Bad method: ~S" (rrtype-method rrt))))))))
    (let ((children (second node)))
      ;; Remove any empty children
      (maphash #'(lambda (key value) 
		   (if (empty-node-p value) 
		       (remhash key children)))
	       children)
      ;; Recurse expiration through children
      (maphash #'(lambda (key value) (declare (ignore key)) (expire-records now value)) children))))

(defun expire-loop ()
  (ensure-db)
  (let ((*print-pretty* nil))
    (loop
      (let ((now (get-universal-time)))
	;;(format t "now is ~D~%" now)
	;;(format t "*nextttl* is ~D~%" *nextttl*)
	;;(format t "there are ~D seconds until then.~%" (- *nextttl* now))
	(if (>= now *nextttl*)
	    (progn
	      ;;(format t "doing expires.~%")
	      (setf *nextttl* (+ now most-positive-fixnum))
	      (expire-records now)))
	(catch 'wake (sleep (- *nextttl* now)))))))

(defun wake-expire-loop ()
  (process-interrupt *expireprocess* #'(lambda () (throw 'wake nil))))

;; end expiration section

;;;;
;;;; resolver section
;;;;

#+allegro
(defparameter *ids-in-use* (make-hash-table :values nil))

#+allegro
(defun choose-id ()
  (let (id)
    (without-scheduling
      (loop
	(setf id (1+ (random 65535)))
	(if (not (gethash id *ids-in-use*))
	    (progn
	      (puthash-key id *ids-in-use*)
	      (return id)))))))
#-allegro
(defparameter *ids-in-use* (make-hash-table))

#-allegro
(defun choose-id ()
  (let (id)
    (without-scheduling
      (loop
	(setf id (1+ (random 65535)))
	(if (not (gethash id *ids-in-use*))
	    (progn
	      (setf (gethash id *ids-in-use*) t)
	      (return id)))))))

(defun release-id (id)
  (remhash id *ids-in-use*))

(defmacro with-msg-id ((id) &body body)
  `(let ((,id (choose-id)))
     (unwind-protect
	 (progn ,@body)
       (release-id ,id))))
  
	  

(defstruct expectedresponse
  id
  peeraddr
  peerport
  gate
  addtime
  msg
  qname
  coverage ;; what domain this nameserver covers (nil if root)
  )


;; http://cr.yp.to/djbdns/notes.html
(defun message-disposition (msg qname)
  (block nil
    (let* ((flags (msg-flags msg))
	   (rcode (getrcode flags))
	   (qtype (msg-qtype msg))
	   (rrt (code-to-rrtype qtype)))
      ;; Error conditions first.
      ;; Check for rcodes that we know about.
      (if (not (member rcode 
		       `(,*rcodeOKAY* ,*rcodeFORMATERROR* 
				      ,*rcodeSERVERFAILURE* ,*rcodeNAMEERROR* 
				      ,*rcodeNOTIMPLEMENTED* ,*rcodeREFUSED*)))
	  (progn
	    (format t "Received unrecognized response code ~S.~%" rcode)
	    (return (list :badserver))))

      (if (or (= rcode *rcodeNOTIMPLEMENTED*)
	      (= rcode *rcodeREFUSED*))
	  (return (list :badserver)))

      (if (= rcode *rcodeFORMATERROR*)
	  (progn
	    (format t "Possible bug.  A nameserver returned a FORMAT ERROR notice.~%")
	    (return (list :badserver))))
      
      ;; NXDOMAIN means that there are definitely not records of any type
      ;; for the requested name.
      (if (= rcode *rcodeNXDOMAIN*)
	  (return (list :nxdomain (negative-ttl msg) (msg-authority msg))))

      (if (or (and (eq (rrtype-keyword rrt) :any) (> (length (msg-answer msg)) 0))
	      (> (count-answers-that-match msg qname (rrtype-keyword rrt)) 0))
	  (return (list :answers (msg-answer msg) (msg-authority msg) (msg-additional msg))))

      (let ((res (locate-cname-answer msg qname)))
	(if res
	    (return (list :cname res (msg-answer msg) (msg-authority msg) (msg-additional msg)))))

      (if (and (ns-exists-p msg) (not (soa-exists-p msg)))
	  (return (list :delegation 
			  (msg-authority msg) (msg-additional msg))))

      ;; default.  This means that the name may exist but there are 
      ;; no records of the requested type.
      (return (list :nomatch (negative-ttl msg) (msg-authority msg))))))

(defun locate-cname-answer (msg qname)
  (dolist (rr (msg-answer msg) nil)
    (if (and (equalp (rr-name rr) qname)
	     (eq (rr-type rr) :cname))
	(return rr))))
      
(defun count-answers-that-match (msg qname type)
  (count-if (lambda (rr)
	      (and (equalp (rr-name rr) qname)
		   (eq (rr-type rr) type)))
	    (msg-answer msg)))
	  
(defun soa-exists-p (msg)
  (find-if #'(lambda (rr) (eq (rr-type rr) :soa))
	   (msg-authority msg)))

(defun ns-exists-p (msg)
  (find-if #'(lambda (rr) (eq (rr-type rr) :ns))
	   (msg-authority msg)))

(defun negative-ttl (msg)
  (let ((rr (soa-exists-p msg)))
    (if rr (soa-minimum rr) 0)))

	    

;; Only used to check delegation information we've received.
;; If it came from a server that's supposed to cover (test franz com)
;; and it directs us to (franz com) or higher, then this nameserver
;; is lame for the domain we were interested in.

(defun lame-p (coverage authority)
  (not (subdomain-p (rr-name (first authority)) coverage :strict t)))
  

;; 'a' is an 'A' resource record for the nameserver
(defun try-nameserver (a msg coverage)
  (block nil
    (with-msg-id (id)
      (let (er newmsg timeout disp)
	(setf (msg-peeraddr msg) (rr-data a))
	(setf (msg-id msg) id)
	(if *verbose* 
	    (format t "~%Asking ~A about ~A~%" a 
		    (domain-to-string (msg-qname msg))))
	(setf er (add-expected-response msg coverage))
	;; see if we have stats we can draw from
	(setf timeout (rr-responsetime a))
	(if timeout
	    (if (< timeout internal-time-units-per-second) ;; very likely
		(setf timeout 2)
	      (setf timeout 
		(min *maxquerytimeout* 
		     (ceiling (/ (* 2 timeout) internal-time-units-per-second)))))
	  (setf timeout *maxquerytimeout*))
	
	(send-msg msg)
	
	;;(if *verbose* (format t "timeout is ~D~%" timeout))
	
	(if* (process-wait-with-timeout "Waiting for response" timeout #'gate-open-p (expectedresponse-gate er))
	   then ;; we got an answer
		(setf newmsg (expectedresponse-msg er))
		;; record stats   XXX - this should be a decaying average
		(setf (rr-responsetime a) (- (get-internal-real-time) (expectedresponse-addtime er)))

		(setf disp 
		  (message-disposition newmsg (expectedresponse-qname er)))
		
		;;(format t "Response: ~S~%" newmsg)
		(if *verbose* (format t "Response disposition: ~S~%" disp))
		;; possible responses
		;; :badserver, :nxdomain, :answers, :delegation, :nomatch
		;; :cname
		
		(if (eq (first disp) :badserver)
		    (return :tryanotherserver))

		(if (and (eq (first disp) :delegation)
			 (lame-p coverage (second disp)))
		    (progn
		      (format t "Lame server: ~A was supposed to know about ~A~%"
			      a
			      (list-to-string coverage))
		      (return :lame)))
		
		;; default.. just return in.
		(return disp)

	   else	;;; no answer received
		(setf (rr-responsetime a) most-positive-fixnum) ;; really bad score
		(remove-expected-response msg)
		(if *verbose*
		    (format t "Timed out waiting for response from ~A~%" (number-to-ipaddr-string (msg-peeraddr msg))))
			;;; just loop and try another address
		(return :tryanotherserver))))))

;;; a-list is a list of nameserver address RRs
(defun try-all-nameservers (a-list msg coverage)
  (let ((lamecount 0))
    (dolist (a a-list)
      (let ((res (try-nameserver a msg coverage)))
	(cond
	 ((eq res :lame)
	  (incf lamecount)) ;; and loop
	 ((eq res :tryanotherserver)
	  ) ;; just loop
	 ;; everything else gets passed up the caller.
	 (t
	  (return-from try-all-nameservers res)))))
    (if (= (length a-list) lamecount)
	;;; Do I want to return a keyword that indicates this state?  The results are the same
	;;; (SERVFAIL) either way.
	(format t "All known nameservers lame.~%")) ;; XXX -need to say for which domain.
    :nousefulresponse))

;; Returns whatever try-all-nameservers returns.
;; called by query-helper-tryloop. and now resolve-inner
;; Doesn't cause recursion.
(defun do-remote-query (domain rrt addrlist coverage)
  (if (stringp domain)
      (setf domain (string-to-list domain)))
  (let ((msg (make-msg 
	      :msgtype :query
	      :flags (ash #.*opcodeQUERY* (- *opcodeshift*))
	      :qname domain
	      :qtype (rrtype-code rrt)
	      :qclass *classIN*
	      :peerport *dnsport*)))
    (try-all-nameservers addrlist msg coverage)))

(defun resolve-remote (domain rrt &key (depth 0) (nameservers (root-nameservers)) (coverage nil))
  (if (keywordp rrt)
      (setf rrt (keyword-to-rrtype rrt)))
  (let ((res (resolve-inner domain rrt :nameservers nameservers :coverage coverage :depth depth)))
    (cond
     ((and (listp res) (eq (first res) :nomatch))
      (cache-negative domain (second res) rrt)
      res)
     ((and (listp res) (eq (first res) :nxdomain))
      (cache-nxdomain domain (second res))
      res)
     ((and (listp res) (eq (first res) :cname))
      (if (>= depth *max-depth*)
	  :maxdepth
	(let ((newres (resolve (rr-data (second res)) rrt (1+ depth))))
	  ;;(format t "res was ~S and newres is ~S~%" res newres)
	  (if (and (listp newres) (eq (first newres) :answers))
	      (setf (second newres) (append (second newres) (third res))))
	  newres)))
     (t
      res))))

;; This is the loop that digs down until it finds the right nameserver to
;; answer the question.
(defun resolve-inner (domain rrt &key (nameservers (root-nameservers)) (coverage nil) (depth 0))
  (block nil
    (if (stringp domain)
	(setf domain (string-to-list domain)))
    (let ((addrlist (resolve-nameservers nameservers :depth depth))
	  res)
      (loop
	(if (null addrlist)
	    (progn
	      (if *verbose* 
		  (format t "Couldn't determine the addresses for any nameservers in ~A.~%" nameservers))
	      (return :no-nameservers)))
	(setf res (do-remote-query domain rrt addrlist coverage))
	(cond 
	 ((and (listp res) (eq (first res) :delegation))   ;; :delegation authority additionals
	  (if* (null (third res))
	     then
		  (if (>= depth *max-depth*)
		      (progn
			(format t "resolve-inner: Got a glueless delegation ~S but max depth has been reached.~%"
				(second res))
			(return :servfail)))
		  (if *verbose* (format t "Chasing glueness delegation: ~S~%" (second res)))
		  (if (null (setf (third res) (resolve-nameservers (second res) :depth (1+ depth))))
		      (progn
			(format t "resolve-inner: resolve-nameservers couldn't help our glueness delegation. Giving up.~%")
			(return :servfail))))
	  
	  ;; Some sanity checks.
	  (if (not (every (lambda (rr) (eq (rr-type rr) :a)) (third res)))
	      (error "Weird!  Got at least one non-A record in the additional section of a delegation: ~S" res))
	  (if (not (every (lambda (rr) (eq (rr-type rr) :ns)) (second res)))
	      (error "Weird!  Got at least one one-NS record in the authority section of a delegation: ~S" res))
	  ;; Make sure the delegation is the same on all the NS records
	  (if (not (every (lambda (rr) (equalp (rr-name rr) (rr-name (first (second res))))) (second res)))
	      (error "Weird!  Not all of the NS records in the authority section are for the same subdomain: ~S" res))
	  (setf nameservers (second res))
	  (setf addrlist (randomize-list (third res)))
	  (setf coverage (rr-name (first (second res))))
	  (if *verbose*
	      (progn
		(format t "Nameservers is now ~A~%" nameservers)
		(format t "Addrlist is now ~A~%" addrlist)
		(format t "Coverage is now ~A~%" (list-to-string coverage)))))
	 ((and (listp res) (eq (first res) :answers))
	  (return res))
	 ((and (listp res) (eq (first res) :cname))
	  (let ((cname-disp (cname-disposition (second res) rrt (third res))))
	    (if (eq cname-disp :answers)
		(return (cons :answers (cddr res))))
	    (return (list :cname (second cname-disp) (third res) (fourth res) (fifth res)))))
	 ((eq res :nousefulresponse)
	  ;; didn't hear back from any of the known nameservers.  In case we have wrong, outdated, or
	  ;; incomplete NS record info, un-cache all NS records and hope for the best the next time around.
	  ;; XXX -- not done yet
	  
	  (return :servfail))
	 ((and (listp res) (or (eq (first res) :nxdomain)
			       (eq (first res) :nomatch)))
	  (return res))
	 (t	
	  (error "do-remote-query returned ~S" res)))))))


(defun cname-disposition (rr rrt answers &optional (depth 0))
  (block nil
    ;; rr is the start rr  (the cname that partially answered our question)
    ;; find records that match the rr-data portion of it.  If there aren't any,
    ;; rr is the end of the chain.  
    
    (let ((matches (remove-if-not (lambda (x) (equalp (rr-name x) (rr-data rr))) answers)))
      (if (null matches)
	  (return (list :end rr)))
      ;; There are matches...
      ;;   if one matches our original query type, we have answers already
      (if (find-if (lambda (x) (eq (rr-rrtype x) rrt)) matches)
	  (return :answers))
      ;; No records match our original query type.  Check for another cname redirection
      (let ((newrr (find-if (lambda (x) (eq (rr-type x) :cname)) matches)))
	(if (null newrr)
	    (error "cname-disposition: Something weird is happening"))
	(if (>= depth *max-depth*)
	    (return :maxdepth))
	(cname-disposition newrr rrt answers (1+ depth))))))

;; Caches the fact that there aren't records for a particular
;; name and query type.
(defun cache-negative (domain ttl rrt)
  (if (> ttl 0)
      (let* ((rr (make-rr
		  :type (rrtype-keyword rrt)
		  :rrtype rrt
		  :ttl (+ (get-universal-time) ttl)
		  :name domain
		  :negative t))
	     (node (ensure-node domain nil))
	     (leaf (first node))
	     (writer (rrtype-writer rrt)))
	(case (rrtype-method rrt)
	  (:single 
	   (funcall writer leaf rr))
	  (:multi
	   (funcall writer leaf (list rr)))
	  (t
	   (error "Bad method ~S" (rrtype-method rrt)))))))

;; Caches the fact that there are no records of any type for a 
;; particular name.
(defun cache-nxdomain (domain ttl)
  (if (<= ttl 0)
      (return-from cache-nxdomain))
  (dolist (keyword *supported-types*)
    (cache-negative domain ttl (keyword-to-rrtype keyword))))

(defun root-nameservers ()
  (let ((nameservers (locate-rr "." 'leaf-ns)))  
    (if (null nameservers) ;; they must have expired.  Reload from the hints file.
	(progn
	  (reload-cache)
	  (setf nameservers (locate-rr "." 'leaf-ns))
	  (if (null nameservers)
	      (error "root-nameservers: Failed to get list of root nameservers.  Something is terribly wrong"))))
    ;; there should never be any negative rr's.  But check to make sure there are no bugs
    (if (any-rrs-negative-p nameservers)
	(error "root-nameservers: Ack!! There are negative rrs for the root nameservers!"))
    nameservers))

;; called twice from resolve-inner... once from positive answer
;; One particular time is to get glue for glueless NS delegations.
(defun resolve-nameservers (nameservers &key (depth 0))
  (let (a-records)
    (dolist (rr nameservers)
      (let ((res (locate-rr (rr-data rr) 'leaf-a)))
	(if* (any-rrs-negative-p res)
	   then
		;; This is worth a complaint.  Someone said this name was a nameserver
		;; for some domain but we have a negative record for that name.
		(if *verbose*
		    (format t "Screwed up delegation. ~S was supposed to be a nameserver for ~S but ~S has a negative record.~%"
			    (list-to-string (rr-data rr))
			    (list-to-string (rr-name rr))
			    (list-to-string (rr-data rr))))
	   else
		;; nil or some records.  nil means we need to recurse.
		(if (null res)
		    (if (>= depth *max-depth*)
			(format t "Maximum depth reached while trying to resolve nameserver ~A~%" 
				(list-to-string (rr-data rr)))
		      (setf res (remote-resolve-addresses-of (rr-data rr) (1+ depth)))))
		;; Got some info.  
		(setf a-records (append a-records res)))))
    (randomize-list a-records)))
	    
(defun randomize-list (list)
  (if (null list)
      nil
    (let ((len (length list)))
      (if (= len 1)
	  list
	(let ((choice (nth (random len) list)))
	  (cons choice (randomize-list (remove choice list))))))))

;; Nicer interface to resolve
;; Returns list of A records found.. or nil
(defun remote-resolve-addresses-of (name depth)
  (let ((res (resolve name :a depth)))
    (if (and (listp res) (eq (first res) :answers))
	(remove-if-not (lambda (rr) (eq (rr-type rr) :a)) (second res))
      nil)))
  

;; Does cache checking first.
(defun resolve (domain rrt &optional (depth 0))
  (block nil
    (if (stringp domain)
	(setf domain (string-to-list domain)))
    (if (keywordp rrt)
	(setf rrt (keyword-to-rrtype rrt)))
    (multiple-value-bind (node exact) (locate-node domain)
      (if exact
	  (let* ((leaf (first node))
		 (rrs (funcall (rrtype-reader rrt) leaf))
		 cname)
	    (if rrs 
		(return (if (any-rrs-negative-p rrs)
			    (nomatch-answer domain)
			  (positive-answer domain rrt rrs depth))))
	    ;; no rrs found.  See if there's a (non-negative) cname.
	    (if (and (setf cname (leaf-cname leaf))
		     (not (any-rrs-negative-p cname)))
		(let (res)
		  (if (>= depth *max-depth*)
		      (return :maxdepth))
		  (setf res (resolve (rr-data cname) rrt (1+ depth)))
		  (if (and (listp res) (eq (first res) :answers))
		      ;; the order matters to some clients.  Since
		      ;; send-msg reverses the list, we need to make
		      ;; sure things are in reverse order here.
		      (setf (second res) (append (second res) (list cname))))
		  (return res)))))
      
      ;; If we're authoritative for the domain in question, we can return
      ;; a definite negative.
      (if (leaf-authority (first node))
	  (return (nxdomain-answer domain)))
      
      ;; I'm not sure if 'servfail' is too much information or not
      (if (secondary-p domain)
	  (return :servfail))
      
      ;; Need to ask other machines.
      ;; XXX -- we should only do this if the recursion-desired bit was set.
      ;;        If it isn't set, we should just return the most specific delegation
      ;;        information we have cached.
      (if (>= depth *max-depth*)
	  :maxdepth
	(multiple-value-bind (nameservers coverage)
	    (locate-nearest-nameservers-with-glue domain)
	  (resolve-remote domain rrt :depth (1+ depth) :nameservers nameservers :coverage coverage))))))

;;; Returns list of nameserver rrs and coverage
(defun locate-nearest-nameservers-with-glue (domain)
  (with-dblock
      (locate-nearest-nameservers-with-glue-help (locate-node domain))))
    
(defun locate-nearest-nameservers-with-glue-help (node)
  (let* ((nnn (locate-nearest-nameservers-node node))
	 (leaf (first nnn))
	 a-records)
    (dolist (ns-rr (leaf-ns leaf))
      (setf a-records (append a-records (locate-rr (rr-data ns-rr) 'leaf-a))))
    (if a-records
	(values (leaf-ns leaf) (rr-name (first (leaf-ns leaf))))
      (if (eq nnn *db*)
	  (progn
	    (reload-cache)
	    (values (leaf-ns *db*) nil))
	(locate-nearest-nameservers-with-glue-help (leaf-parent leaf))))))

(defun any-rrs-negative-p (rrs)
  (if (rr-p rrs)
      (rr-negative rrs)
    (find-if #'rr-negative rrs)))

(defun nomatch-answer (domain)
  (let ((soanode (locate-nearest-soa-node domain)))
    (if soanode
	(let ((soa (leaf-soa (first soanode))))
	  (list :nomatch (soa-minimum soa) (list soa)))
      (list :nomatch 0 nil))))

(defun nxdomain-answer (domain)
  (let ((soanode (locate-nearest-soa-node domain)))
    (if soanode
	(let ((soa (leaf-soa (first soanode))))
	  (list :nxdomain (soa-minimum soa) (list soa)))
      (list :nxdomain 0 nil))))


;;; typical authority/additional is authority section w/ nearest nameservers and
;;;  additional w/ the addresses for those nameservers.... 

;;; A: Typical
;;; NS:  +additional: address of NS records in answer (only if cached??)
;;;      -authority: SOA record  (i.e, typical)
;;; CNAME: typical
;;; SOA: typical
;;; PTR: typical
;;; MX: typical
;;; SRV: probably typical

(defun positive-answer (domain rrt rrs depth)
  (if (not (listp rrs))
      (setf rrs (list rrs)))
  (let ((res (list :answers rrs nil nil)) ;; :answers rrset authority additional
	(ns-node (locate-nearest-nameservers-node domain)))
    (if ns-node
	(let* ((ns-leaf (first ns-node))
	       (nslist (leaf-ns ns-leaf)))
	  (setf (third res) nslist)
	  (setf (fourth res) (resolve-nameservers nslist :depth depth))
	  (if (eq (rrtype-keyword rrt) :ns)   ;; remove redundant information that would result in NS queries
	      (setf (third res) nil))))
    res))


;;; responses will be stuffed onto a list and processed by some other code

(defparameter *expectedresponses* nil)
(defparameter *expectedresponseslock* (make-process-lock :name "*responselist* lock"))

(defun add-expected-response (msg coverage)
  (let ((er (make-expectedresponse
	     :id (msg-id msg)
	     :peeraddr (msg-peeraddr msg)
	     :peerport (msg-peerport msg)
	     :gate (make-gate nil)
	     :qname (msg-qname msg)
	     :coverage coverage
	     :addtime (get-internal-real-time))))
    (with-process-lock (*expectedresponseslock*)
      (push er *expectedresponses*))
    er))
   
(defun remove-expected-response (msg)
  (with-process-lock (*expectedresponseslock*)
    (setf *expectedresponses*
      (remove msg *expectedresponses* :test #'(lambda (msg er) (= (msg-id msg) (expectedresponse-id er)))))))

;; RFC1035 says that some nameservers send responses from a different addresses
;; than that which you sent the request to.   RFC2181 says that most clients
;; expect to receive responses w/ the same source address as the original query
;; destination... so I do it here as well.
(defun expected-response-match-p (msg er)
  (and
   (= (msg-id msg) (expectedresponse-id er))
   (= (msg-peeraddr msg) (expectedresponse-peeraddr er))
   (= (msg-peerport msg) (expectedresponse-peerport er))))

(defun locate-expected-response (msg)
  (let ((er (find msg *expectedresponses* :test #'expected-response-match-p)))
    (if* er
       then
	    (setf *expectedresponses* (remove er *expectedresponses*))
	    er
       else
	    nil)))

;;; called from handle-message.
(defun handle-response (msg)
  (with-process-lock (*expectedresponseslock*)
    (let ((er (locate-expected-response msg)))
      (if* er
	 then
	      ;;(if *verbose* (format t "received message: ~S~%" msg))
	      ;;(format t "er is ~S~%" er)
	      (setf (expectedresponse-msg er) msg)
	      (add-msg-data-to-db msg (expectedresponse-coverage er))
	      (open-gate (expectedresponse-gate er))
	 else
	      (if *verbose* (format t "Unexpected message received: ~S~%" msg))))))

;;; We never update the database for zones over which we're
;;; authoritative.  RFC1035 says that you should either replace the
;;; data in the cache.. or not replace it..  data should never be
;;; combined.  XXXX - This isn't handled yet.  Use www.bart.gov as a
;;; test.  a.root-servers.net returns different NS information than
;;; ns1.ptld.twtelecom.net but the info ends up being combined.

;;; To do this properly, I would need to scan through the message
;;; parts and separate the RRs into their proper RRsets (they won't all be
;;; for the same name).   rrtype will need a slot that specifies a function
;;; which is used to determine if the information we just received is better
;;; than the cached information (i.e, a should-update function).

;;; collect all the RRs... remove ones that aren't in-bailiwick.. and ones
;;;   for which we're authoritative.
;;; make a list of groups (RRsets).
;;; process them (may not even need the should-update functions).

(defun get-in-bailiwick-rrs (msg coverage)
  (let (res)
    (dolist (func '(msg-answer msg-authority msg-additional))
      (dolist (rr (funcall func msg))
	(let* ((node (ensure-node (rr-name rr) nil))
	       (leaf (first node)))
	  (if (and (not (leaf-authority leaf))
		   (subdomain-p (rr-name rr) coverage))
	      (push rr res)))))
    res))

;;; Returns t if child is a subdomain of parent.  That means that parent list
;;; must be a prefix of child list.  If parent is nil (indicating the root
;;; node), it is definitely the prefix of any list.  'strict' means 
;;; a proper subdomain (i.e., (com franz) is not a strict subdomain 
;;; of (com franz)).
(defun subdomain-p (child parent &key strict)
  (let ((childlen (length child))
	(parentlen (length parent))
	(test (if strict #'> #'>=)))
    (and (funcall test childlen parentlen)
	 (equalp (subseq child 0 parentlen) parent))))


;; An RRSet is a list of RRs that have the same label and type.
(defun group-into-rrsets (rrs)
  (let (rrsets)
    (loop
      (if (null rrs)
	  (return))
      (multiple-value-bind (rrset remainder)
	  (grab-matching-rrs rrs (rr-name (first rrs)) (rr-type (first rrs)))
	(push rrset rrsets)
	(setf rrs remainder)))
    rrsets))

(defun grab-matching-rrs (rrs matchname matchtype)
  (let (rrset remainder)
    (dolist (rr rrs)
      (if (and (equalp (rr-name rr) matchname)
	       (eq (rr-type rr) matchtype))
	  (push rr rrset)
	(push rr remainder)))
    (values rrset remainder)))

;;; We only cache information from in-bailiwick nameservers.

(defun add-msg-data-to-db (msg coverage)
  (with-dblock
      (dolist (rrset (group-into-rrsets (get-in-bailiwick-rrs msg coverage)))
	(let* ((rrt (rr-rrtype (first rrset)))
	       (method (rrtype-method rrt))
	       (writer (rrtype-writer rrt))
	       (node (ensure-node (rr-name (first rrset)) nil))
	       (leaf (first node)))
	  (case method
	    (:single
	     (update-nextttl (first rrset))
	     (funcall writer leaf (first rrset)))
	    (:multi
	     (dolist (rr rrset)
	       (update-nextttl rr))
	     (funcall writer leaf rrset))
	    (t 
	     (error "Ack! Bogus rrmethod!")))))))

;;; end resolver section


;;
;; secondary nameserver stuff
;;

(defstruct (secondary (:predicate nil)) ;; avoid conflicting definition of secondary-p
  domain
  domain-as-list
  filename
  masters
  refreshat 
  refresh ;; from SOA
  retry ;; from SOA
  expire ;; from SOA
  expireat
  expired)

(defparameter .secondaries. nil)
;; how often to try to do an initial zone transfer
(defparameter *initialsecondaryretry* 3600) 


;; loop
;; if awakened
;; see if any expireat times are < now.  If so, remove the zone.
;; see if any refreshat times are < now. 
;;  if so, attempt to do zone transfer.
;;  if transfer fails, set refreshat to now+retry
;;  if transfer is good, set refreshat to now+refresh and expireat to now+expire
;; compute new time to sleep based on nearest refreshat or expireat time.
;; sleep

;; the nameserver should never respond to answers about an expired zone.

(defun secondary-loop ()
  (let ((sleeptime 0)
	now)
    (loop
      ;;(format t "sleeping for ~D seconds~%" sleeptime)
      (catch 'wake (sleep sleeptime))
      (setf now (get-universal-time))
      (setf sleeptime most-positive-fixnum)
      (dolist (sec .secondaries.)
	(if (and (not (secondary-expired sec))
		 (> now (secondary-expireat sec)))
	    (expire-zone sec)) 
	(if (> now (secondary-refreshat sec))
	    (if (refresh-zone sec) ;; sets refresh, retry, and expire times upon success
		(progn
		  (setf (secondary-refreshat sec) (+ now (secondary-refresh sec)))
		  (setf (secondary-expireat sec) (+ now (secondary-expire sec))))
	      (setf (secondary-refreshat sec) (+ now (secondary-retry sec)))))
	(let ((refresh (- (secondary-refreshat sec) now)))
	  (if (< refresh sleeptime)
	      (setf sleeptime refresh)))
	(when (not (secondary-expired sec))
	  (let ((expire (- (secondary-expireat sec) now)))
	    (if (< expire sleeptime)
		(setf sleeptime expire))))))))

(defun initialize-secondaries ()
  (setf .secondaries. nil)
  (dolist (s *secondarylist*)
    (push (make-secondary :domain (first s)
			  :domain-as-list (string-to-list (first s))
			  :filename (second s)
			  :masters (third s)
			  :refreshat 0  ;; so it'll happen as soon as secondary-loop starts
			  :retry *initialsecondaryretry*
			  :expired t
			  )
	  .secondaries.)))

(defun secondary-p (domain)
  (if (stringp domain) 
      (setf domain (string-to-list domain)))
  (dolist (sec .secondaries.)
    (if (subdomain-p domain (secondary-domain-as-list sec))
	(return t))))
  

(defun expire-zone (sec)
  (delete-zone (secondary-domain sec)))

(defun refresh-zone (sec &optional master)
  (let ((masters (if master (list master) (secondary-masters sec))))
    (if (probe-file (secondary-filename sec))
	(read-zone-file (secondary-domain sec) (secondary-filename sec) t)) 
    (let* ((rrlist (transfer-zone (secondary-domain sec) masters))
	   (res 
	    (cond
	     ((eq rrlist :nogood)
	      ;; couldn't get anything... try again later, perhaps
	      nil
	      )
	     ((eq rrlist :up-to-date)
	      (format t "zone is ~A is up to date.~%" (secondary-domain sec))
	      t
	      )
	     ((listp rrlist)
	      (rebuild-zone (secondary-domain sec) rrlist)
	      (save-zone-to-file (secondary-domain sec) (secondary-filename sec))
	      t)
	     (t
	      (error "Unexpected response from transfer-zone: ~S" rrlist)))))
      (if res
	  (multiple-value-bind (node exact) (locate-node (secondary-domain sec))
	    ;; some sanity checks.. Probably redundant.
	    (if (not exact)
		(error "Ack! Couldn't find node for ~A after reload!" (secondary-domain sec)))
	    (let* ((leaf (first node))
		   (soa (leaf-soa leaf)))
	      (if (null soa)
		  (error "Ack! There is no SOA RR for domain ~A after reload!" (secondary-domain sec)))
	      (setf (secondary-expired sec) nil)
	      (setf (secondary-refresh sec) (fourth (rr-data soa)))
	      (setf (secondary-retry sec) (fifth (rr-data soa)))
	      (setf (secondary-expire sec) (sixth (rr-data soa))))))
      res)))
	
  
(defun get-rrlist-from-sock (sock master)
  (block nil
    (let* ((bufsize (logior (ash (read-byte sock) 8) (read-byte sock)))
	   (buf (make-array bufsize :element-type '(unsigned-byte 8)))
	   (pos 0))
      (while (< pos bufsize)
	     (setf pos (read-sequence buf sock :start pos)))
      (multiple-value-bind (rmsg status) (make-msg-from-buf buf bufsize master *dnsport* :tcp sock t)
	(unless (eq status :ok)
	  (error "Got unexpected status from make-msg-from-buf: ~S" status))
	(if (nonzerop (getrcode (msg-flags rmsg)))
	    (error "get-rrlist-from-sock: Got error code ~D" (getrcode (msg-flags rmsg))))
	(msg-answer rmsg)))))


(defun get-current-serial (domain)
  (multiple-value-bind (node exact) (locate-node domain)
    (let ((leaf (first node)))
      (if (and exact (leaf-soa leaf))
	  (soa-serial (leaf-soa leaf))
	0))))

;;; XXX - this thing needs to have a timeout.
(defun transfer-zone (domain masters)
  (let (sock msg rrlist)
    (dolist (master masters :nogood)
      (format t "transfer-zone: Trying to connect to ~A for ~A~%" 
	      master domain)
      (unwind-protect 
	  (handler-case 
	      (progn
		(setf sock (socket:make-socket :type :stream
					       :address-family :internet
					       :local-host *dnshost*
					       :remote-host master
					       :remote-port *dnsport*))
		;;(format t "zone transfer socket fd ~D~%" (excl::stream-input-fn sock))
		(with-msg-id (id)
		  (setf msg (make-msg :id id
				      :flags 0
				      :peeraddr master
				      :peerport *dnsport*
				      :peertype :tcp
				      :peersocket sock
				      :msgtype :axfr
				      :qname domain
				      :qtype *typeAXFR*
				      :qclass *classIN*))
		  (send-msg msg))
		(setf rrlist (get-rrlist-from-sock sock master))
		(if (null rrlist)
		    (error "Got no answers from ~A~%" master))
		(if (not (eq (rr-type (first (last rrlist))) :soa))
		    (error "Expected first RR to be SOA (but was ~S)~%" (first (last rrlist))))
		(if (<= (soa-serial (first (last rrlist))) (get-current-serial domain))
		    (return :up-to-date))
		;; Accept the rest of the transmission
		(loop
		  (setf rrlist (append (get-rrlist-from-sock sock master) rrlist))
		  (if (eq (rr-type (first rrlist)) :soa)
		      (return)))
		(format t "transfer completed.~%")
		(return rrlist))
	    (t (c)
	      (format t "transfer-zone:  Encountered error ~A.  Skipping this master.~%" c)))
	;; cleanup form
	(if* sock
	   then
		;; jkf recommendation
		(ignore-errors (force-output sock))
		(ignore-errors (close sock :abort t))
		(setf sock nil))))))

	  

;; rrlist should have an SOA rr as the first and last elements.
;;; XXX - want to make sure this works even in the case that we have no existing info
;;; for this zone.
(defun rebuild-zone (domain rrlist)
  (if (stringp domain)
      (setf domain (string-to-list domain)))
  (let ((node (ensure-node domain t)))
    ;; some sanity checks
    (unless (>= (length rrlist) 2)
      (error "rrlist is too short!: ~S~%" rrlist))
    (unless (and (eq (rr-type (first rrlist)) :soa)
		 (eq (rr-type (first (last rrlist))) :soa))
      (error "rrlist should begin and end with SOA rr's"))
    ;; XXX - perhaps another check to confirm that the two SOAs are equalp.
    (pop rrlist)
    (with-dblock
      (delete-zone node)
      (dolist (rr rrlist)
	;;; we're only authoritative if the node isn't a delegation.
	(let* ((newnode (ensure-node (rr-name rr) (or (not (eq (rr-type rr) :ns)) (equalp domain (rr-name rr)))))
	       (leaf (first newnode)))
	  (case (rr-type rr)
	    (:a 
	     (add-or-update-a-record leaf rr))
	    (:ns
	     (add-or-update-ns-record leaf rr))
	    (:mx
	     (add-or-update-mx-record leaf rr))
	    (:srv
	     (add-or-update-srv-record leaf rr))
	    ((:cname :ptr :soa)
	     (let ((writer (intern (format nil "~A-~A-~A" 'leaf (rr-type rr) 'writer))))
	       (funcall writer leaf rr)))
	    (t 
	     (error "Unsupported type ~S~%" (rr-type rr)))))))))

(defun leaf-node-p (node)
  (= 0 (hash-table-count (second node))))

(defun delete-zone (node)
  (if (stringp node)
      (setf node (locate-node node)))
  (with-dblock
    (let (remlist)
      (maphash #'(lambda (name node)
		   (if (null (leaf-ns (first node)))
		       (if (leaf-node-p node)
			   (push name remlist)
			 (delete-zone node))))
	       (second node))
      (dolist (key remlist)
	(remhash key (second node)))
      (invalidate-node node))))

;; for intermediate nodes we can't delete
(defun invalidate-node (node)
  (let ((leaf (first node)))
    (dolist (ktype *supported-types*)
      (funcall (rrtype-writer (keyword-to-rrtype ktype)) leaf nil))
    (setf (leaf-valid leaf) nil)
    (setf (leaf-authority leaf) nil) 
    ))

;; This should only be use for domains for which we're authoritative so
;; we don't have to worry about negative records.
(defun save-zone-to-file (domain filename)
  (multiple-value-bind (node exact) (locate-node domain)
    (let ((soanode (locate-nearest-soa-node node)))
      (if (or (not exact) (not (eq soanode node)))
	  ;; XXX - this error message could probably use rewording.
	  (error "save-zone-to-file must be called with the start of an already-cached zone!"))
      (with-open-file (f filename
		       :direction :output
		       :if-exists :supersede)
	(dumpleaf (first node) (leaf-name (first node)) f)
	;; there's probably a better way to do this.. but I can't remember
	(defun save-zone-to-file-helper (label node)
	  (declare (ignore label))
	  (let ((leaf (first node)))
	    (if (null (leaf-ns leaf)) ;; regular RRs
		(progn
		  (dumpleaf leaf (leaf-name leaf) f) ;; this node
		  ;; and children
		  (maphash #'save-zone-to-file-helper (second node)))
	      ;; zone cut.. just write out NS records
	      (dolist (ns (leaf-ns leaf))
		(dumprr ns (leaf-name leaf) f)))))
	(maphash #'save-zone-to-file-helper (second node))))))


	
;;; DB Dumper


(defun dumpdb (&optional (startnode *db*))
  (with-dblock
    (if (stringp startnode) 
	(setf startnode (locate-node startnode)))
    (dumpdbnode startnode (leaf-name (first startnode))
		(leaf-name (first startnode))  t t)))

(defun dumpdbnode (node name origin stream firsttime) 
  ;;(format t "dumping node ~S~%" node)

  (format t "$ORIGIN ~A~%" 
	  (if (string= origin "")
	      "."
	    origin))
  (if firsttime
      (dumpleaf (first node) name stream))
  (maphash #'(lambda (cname cnode)
	       (dumpleaf (first cnode) cname stream))
	   (second node))
  (maphash #'(lambda (cname cnode)
	       (if (> (hash-table-count (second cnode)) 0)
		   (dumpdbnode cnode cname (leaf-name (first cnode)) stream nil)))
	   (second node))
  )
  

(defun dumpleaf (leaf name stream)
  ;; order of the readers kinda matters.  Normal zone files have the SOA first,
  ;; then NS records.   A records usually follow.  The rest is arbitrary.
  (dolist (reader '(leaf-soa leaf-ns leaf-a leaf-cname 
		    leaf-mx leaf-ptr leaf-srv)) 
    (let ((rrs (funcall reader leaf)))
      (if (listp rrs)
	  (dolist (rr rrs)
	    (dumprr rr name stream))
	(dumprr rrs name stream)))))

(defun dumprr (rr name stream)
  (format stream "~A	" name)
  (rr-printer rr stream :mff t))

(defun empty-leaf-p (leaf)
  (let (res)
    (dolist (type *supported-types*)
      (push (funcall (rrtype-reader (keyword-to-rrtype type)) leaf) res))
    (every #'null res)))

;; This is used for expiration stuff
(defun empty-node-p (node)
  (and (empty-leaf-p (first node))
       (= 0 (hash-table-count (second node)))))


;;; NOTIFY
;;; XXX -- should make sure that we're not already processing a zone transfer.
(defun handle-notify-request (msg)
  (block nil
    (let ((rrt (code-to-rrtype (msg-qtype msg))))
      (format t "Got a NOTIFY request~%")
      (format t "Notification is for ~A, type ~A~%"
	      (domain-to-string (msg-qname msg)) 
	      (rrtype-string rrt))
      
      (if (not (eq (rrtype-keyword rrt) :soa))
	  (return (format t "We don't support NOTIFY for this RR type~%")))
      
      (let ((sec (find (msg-qname msg) .secondaries. 
		       :key (lambda (s) (string-to-list (secondary-domain s))) :test #'equalp)))
	(if (null sec)
	    (return (format t "We're not a secondary for that domain!~%")))
	
	(if (not (member (msg-peeraddr msg) (secondary-masters sec) :key #'parse-ip-addr))
	    (return (format t "NOTIFY received from a host we don't list as a master! (~A)~%" 
			    (number-to-ipaddr-string (msg-peeraddr msg)))))
	
	(send-msg msg) ;; Affirmative response
	(refresh-zone sec (number-to-ipaddr-string (msg-peeraddr msg)))))))

    
;;; we don't send out notify queries yet 
(defun handle-notify-response (msg)
  (declare (ignore msg))
  (format t "Got a NOTIFY response.  Not supported yet~%"))
