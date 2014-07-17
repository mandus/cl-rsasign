;;;; cl-rsasign.lisp

(in-package #:cl-rsasign)

;; "cl-rsasign" goes here. Hacks and glory await!

;; set the crypto-api to use; at this time only openssl-cffi is supported
;(defvar *crypto-api* :openssl-cffi)

(defun decode-rsa-private-key (string &optional (passphrase ""))
  (openssl-decode-rsa-private-key string passphrase))

;(defun decode-rsa-private-key (string &optional (passphrase ""))
;  (decode-rsa-private-key-gf *crypto-api* string passphrase))

(defmacro with-rsa-private-key ((keyvar key &optional passphrase) &body body)
  (let ((thunk (gensym)))
    `(flet ((,thunk (,keyvar) ,@body))
       (declare (dynamic-extent #',thunk))
       (call-with-rsa-private-key #',thunk ,key ,passphrase))))
             
(defun call-with-rsa-private-key (thunk key &optional passphrase)
  (if (stringp key)
      (let ((key (decode-rsa-private-key key passphrase)))
        (unwind-protect
             (funcall thunk key)
          (rsa-free key)))
      (funcall thunk key)))

(defun rsa-private-key-from-file (filename)
  (decode-rsa-private-key 
    (with-open-file (pem-stream filename :direction :input)
      (slurp-stream pem-stream))))

(defun sign (data rsa-private-key &optional (hash-method :sha256))
  "Sign the string in data with the rsa-private-key, using 
   hash-method (default to sha256, sha1 also possible) as the hash-function.
   The signature is returned base64-encoded"
  (openssl-sign data rsa-private-key hash-method))

;(defun sign (data rsa-private-key &optional (hash-method :sha256))
;  "Sign the string in data with the rsa-private-key, using 
;   hash-method (default to sha256, sha1 also possible) as the hash-function.
;   The signature is returned base64-encoded"
;  (sign-gf *crypto-api* data rsa-private-key hash-method))

(defun rsa-free (rsa)
  "Free a structure returned by decode-rsa-private-key. May be a nop for
   garbage collected implementations, but best to overwrite the contents, so
   they don't hang around in RAM."
  (openssl-rsa-free rsa))

;(defun rsa-free (rsa)
;  "Free a structure returned by decode-rsa-private-key. May be a nop for
;   garbage collected implementations, but best to overwrite the contents, so
;   they don't hang around in RAM."
;  (rsa-free-gf *crypto-api* rsa))

;;;
;;; Generic functions dispatched to plug-in implementation
;;; 
;;; openssl-cffi.lisp
;;;
;
;(defgeneric decode-rsa-private-key-gf (api string &optional passphrase))
;
;(defgeneric sign-gf (api data rsa-private-key &optional hash-method))
;
;(defgeneric rsa-free-gf (api rsa))
