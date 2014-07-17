;; 
;; cffi interface to a few cryptographic functions in OpenSSL
;; 
;; I try to use as much as I can from other libraries, and only 
;; implement the absolutely necessary parts here.
;;
;; Implementation is based on the openssl interface in truledger
;; 

(in-package #:cl-rsasign)

(cffi:define-foreign-library libssl
  (:windows "libssl32.dll")
  (:darwin "libssl.dylib")
  (:unix (:or "libssl.so.1.0.0" "libssl.so"))
  (t (:default "libssl3")))

(cffi:define-foreign-library libcrypto
  (:darwin "libcrypto.dylib")
  (:unix (:or "libcrypto.so.1.0.0" "libcrypto.so"))
  (t (:default "libcrypto")))

(cffi:define-foreign-library libeay32
  (:windows "libeay32.dll"))

(defvar *openssl-process* nil)

(defvar *openssl-lock* (fsdb:make-lock "OpenSSL"))

(defmacro with-openssl-lock (() &body body)
  (let ((thunk (gensym)))
    `(flet ((,thunk () ,@body))
       (declare (dynamic-extent #',thunk))
       (call-with-openssl-lock #',thunk))))

(defun call-with-openssl-lock (thunk)
  (let ((process (fsdb:current-process)))
    (if (eq process *openssl-process*)
      (funcall thunk)
      (fsdb:with-lock-grabbed (*openssl-lock* "OpenSSL Lock")
        (unwind-protect
             (progn
               (setq *openssl-process* process)
               (funcall thunk))
          (setq *openssl-process* nil))))))

;; Work around a CFFI bug. (close-foreign-library 'libcrypto)
;; causes the lisp to crash. It is called by (open-foreign-library 'libcrypto)
(let ((sym (find-symbol "CLOSE-FOREIGN-LIBRARY" "CFFI")))
  (when sym
    (setf (symbol-function sym)
          (lambda (&rest rest) (declare (ignore rest))))))

(defparameter $null (null-pointer))

(defcfun ("OPENSSL_add_all_algorithms_conf" open-ssl-add-all-algorithms) :void
  )

;; This is necessary for reading encrypted private keys
(defun add-all-algorithms ()
  (with-openssl-lock ()
    (open-ssl-add-all-algorithms)))

(defun startup-openssl ()
  (load-foreign-library 'libssl)
  (load-foreign-library 'libeay32)
  ;; libcrypto merged into libssl for recent OpenSSL versions.
  (ignore-errors (load-foreign-library 'libcrypto))
  (open-ssl-add-all-algorithms))

;; look at add-startup-function in truledger, maybe we need something similar
;(mcashmapiclient:add-startup-function 'startup-openssl)
(startup-openssl)

(defparameter $pem-string-rsa "RSA PRIVATE KEY")

(defun d2i-RSAPrivateKey ()
  (foreign-symbol-pointer "d2i_RSAPrivateKey"))

(defcfun ("RSA_free" openssl-rsa-free) :void
  (r :pointer))

(defcfun ("BIO_new" %bio-new) :pointer
  (type :pointer))

(defcfun ("BIO_s_mem" %bio-s-mem) :pointer
  )

(defcfun ("BIO_puts" %bio-puts) :int
  (bp :pointer)
  (buf :pointer))

(defun bio-new-s-mem (&optional string)
  (with-openssl-lock ()
    (let ((res (%bio-new (%bio-s-mem))))
      (when (null-pointer-p res)
        (error "Can't allocate io-mem-buf"))
      (when string
        (with-foreign-strings ((sp string :encoding :latin-1))
          (%bio-puts res sp)))
      res)))

(defmacro with-bio-new-s-mem ((bio &optional string) &body body)
  (let ((thunk (gensym)))
    `(let ((,thunk (lambda (,bio) ,@body)))
       (declare (dynamic-extent ,thunk))
       (call-with-bio-new-s-mem ,string ,thunk))))

(defun call-with-bio-new-s-mem (string thunk)
  (let ((bio (bio-new-s-mem string)))
    (unwind-protect
         (funcall thunk bio)
      (bio-free bio))))

(defcfun ("BIO_free" %bio-free) :int
  (a :pointer))

(defun bio-free (bio)
  (with-openssl-lock ()
    (when (eql 0 (%bio-free bio))
      (error "Error freeing bio instance"))))

(defcfun ("PEM_ASN1_read_bio" %pem-asn1-read-bio) :pointer
  (d2i :pointer)
  (name (:pointer :char))
  (bio :pointer)
  (x (:pointer (:pointer :char)))
  (cb :pointer)
  (u :pointer))

(defun %pem-read-bio-rsa-private-key (bio &optional (x $null) (cb $null) (u $null))
  (with-foreign-strings ((namep $pem-string-rsa :encoding :latin-1))
    (%pem-asn1-read-bio (d2i-RSAPrivateKey) namep bio x cb u)))

(defun mem-set-char (val buf &optional (idx 0))
  (setf (mem-ref buf :char idx) val))

(define-condition bad-rsa-key-or-passphrase (simple-error)
  ())

(defun openssl-decode-rsa-private-key (string &optional (passphrase ""))
  "Convert a PEM string to an RSA structure. Free it with RSA-FREE.
   Will prompt for the passphrase if it needs it and you provide nil."
  (with-openssl-lock ()
    (with-bio-new-s-mem (bio string)
      (let ((res (if passphrase
                     (with-foreign-strings ((passp passphrase :encoding :latin-1))
                       (prog1 (%pem-read-bio-rsa-private-key bio $null $null passp)
                         (destroy-passphrase
                          passp (length passphrase) 'mem-set-char)))
                     (%pem-read-bio-rsa-private-key bio))))
        (when (null-pointer-p res)
          (error 'bad-rsa-key-or-passphrase
                 :format-control "Couldn't decode private key from string"))
        res))))

(defcfun ("SHA1" %sha1) :pointer
  (d :pointer)
  (n :long)
  (md :pointer))

(defun sha1 (string &optional (res-type :hex))
  "Return the sha1 hash of STRING.
   Return a string of hex chars if res-type is :hex, the default,
   a byte-array if res-type is :bytes,
   or a string with 8-bit character values if res-type is :string."
  (check-type res-type (member :hex :bytes :string))
  (with-foreign-pointer (md 20)
    (with-foreign-strings ((d string :encoding :utf-8))
      (with-openssl-lock ()
        (%sha1 d (length string) md)))
    (let* ((byte-array-p (or (eq res-type :hex) (eq res-type :bytes)))
           (res (copy-memory-to-lisp md 20 byte-array-p)))
      (if (eq res-type :hex)
          (bin2hex res)
          res))))

(defcfun ("SHA256" %sha256) :pointer
  (d :pointer)
  (n :long)
  (md :pointer))

(defun sha256 (string &optional (res-type :hex))
  "Return the sha256 hash of STRING.
   Return a string of hex chars if res-type is :hex, the default,
   a byte-array if res-type is :bytes,
   or a string with 8-bit character values if res-type is :string."
  (check-type res-type (member :hex :bytes :string))
  (with-foreign-pointer (md 32)
    (with-foreign-strings ((d string :encoding :utf-8))
      (with-openssl-lock ()
        (%sha256 d (length string) md)))
    (let* ((byte-array-p (or (eq res-type :hex) (eq res-type :bytes)))
           (res (copy-memory-to-lisp md 32 byte-array-p)))
      (if (eq res-type :hex)
          (bin2hex res)
          res))))

;; Sign
(defcfun ("EVP_PKEY_new" %evp-pkey-new) :pointer)
(defcfun ("EVP_PKEY_free" %evp-pkey-free) :void
  (pkey :pointer))

(defcfun ("EVP_PKEY_set1_RSA" %evp-pkey-set1-rsa) :int
  (pkey :pointer)
  (key :pointer))

(defcfun ("EVP_sha1" %evp-sha1) :pointer)

(defcfun ("EVP_sha256" %evp-sha256) :pointer)

(defcfun ("EVP_PKEY_size" %evp-pkey-size) :int
  (pkey :pointer))

(defconstant $EVP-MD-CTX-size 32)

(defcfun ("EVP_DigestInit" %evp-sign-init) :int
  (ctx :pointer)
  (type :pointer))

(defcfun ("EVP_DigestUpdate" %evp-sign-update) :int
  (ctx :pointer)
  (d :pointer)
  (cnt :unsigned-int))

(defcfun ("EVP_SignFinal" %evp-sign-final) :int
  (ctx :pointer)
  (sig :pointer)                        ;to EVP_PKEY_size bytes
  (s :pointer)                          ;to int
  (pkey :pointer))

(defcfun ("EVP_MD_CTX_cleanup" %evp-md-ctx-cleanup) :int
  (ctx :pointer))

(defmacro with-evp-pkey ((pkey rsa-key &optional public-p) &body body)
  (let ((thunk (gensym)))
    `(flet ((,thunk (,pkey) ,@body))
       (call-with-evp-pkey #',thunk ,rsa-key ,public-p))))

(defun call-with-evp-pkey (thunk rsa-key public-p)
  (flet ((doit (thunk rsa)
           (let ((pkey (with-openssl-lock () (%evp-pkey-new))))
             (unwind-protect
                  (progn
                    (when (null-pointer-p pkey)
                      (error "Can't allocate private key storage"))
                    (when (eql 0 (with-openssl-lock ()
                                   (%evp-pkey-set1-rsa pkey rsa)))
                      (error "Can't initialize private key storage"))
                    (funcall thunk pkey))
               (unless (null-pointer-p pkey)
                 (with-openssl-lock () (%evp-pkey-free pkey)))))))
    (if public-p
        (with-rsa-public-key (rsa rsa-key) (doit thunk rsa))
        (with-rsa-private-key (rsa rsa-key) (doit thunk rsa)))))

; need the 'base64-encode' from truledger
(defun openssl-sign (data rsa-private-key &optional (hash-meth :sha256) (columns nil))
  "Sign the string in DATA with the RSA-PRIVATE-KEY.
   Return the signature BASE64-encoded. By default, print the result as one long string"
  (check-type data string)
  (with-openssl-lock ()
    (with-evp-pkey (pkey rsa-private-key)
      (let ((type (cond 
                    ((eq hash-meth :sha256) (%evp-sha256)) 
                    ((eq hash-meth :sha1) (%evp-sha1))
                    ; default to signal an error here
                    (t (error "unknown hash method selected")))))
        (when (null-pointer-p type)
          (error "Can't get SHA type structure"))
        (with-foreign-pointer (ctx $EVP-MD-CTX-size)
          (with-foreign-pointer (sig (1+ (%evp-pkey-size pkey)))
            (with-foreign-pointer (siglen (foreign-type-size :unsigned-int))
              (with-foreign-strings ((datap data :encoding :latin-1))
                (when (or (eql 0 (%evp-sign-init ctx type))
                          (unwind-protect
                               (or (eql 0 (%evp-sign-update
                                           ctx datap (length data)))
                                   (eql 0 (%evp-sign-final ctx sig siglen pkey)))
                            (%evp-md-ctx-cleanup ctx)))
                  (error "Error while signing"))
                ;; Here's the result 
                (base64-encode
                 (copy-memory-to-lisp
                  sig (mem-ref siglen :unsigned-int) nil) columns)))))))))


;; 
;; how we get here from crypto.lisp
;;
;
;(defmethod decode-rsa-private-key-gf
;  ((api (eql :openssl-cffi)) string &optional (passphrase ""))
;  (openssl-decode-rsa-private-key string passphrase))
;
;(defmethod sign-gf
;  ((api (eql :openssl-cffi)) data rsa-private-key &optional (hash-meth :sha256))
;  (openssl-sign data rsa-private-key hash-meth))
;
;(defmethod rsa-free-gf 
;  ((api (eql :openssl-cffi)) rsa)
;  (openssl-rsa-free rsa))
;
;
