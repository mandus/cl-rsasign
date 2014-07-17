;;;; cl-rsasign.asd

(asdf:defsystem #:cl-rsasign
  :serial t
  :description "Library for signing message with private rsa-key and sha256 as hash-method"
  :author "Åsmund Ødegård <asmund@xal.no>"
  :license "Apache License v. 2.0"
  :depends-on (#:cffi
               #:cl-base64
               #:cl-autorepo
               #:fsdb)
  :components 
  ((:module src 
    :serial t
    :components
    ((:file "package")
     (:file "cl-rsasign")
     (:file "utils")
     (:file "openssl-cffi")))))


(ql:quickload :cl-autorepo)
(flet ((addit (name)
         (cl-autorepo:add-system
          name (format nil "git://github.com/billstclair/~a.git" name) :git)))
  ;; add non-quicklisp repos here (from billstclair - generalize if other
  ;; sources are needed)
  (addit "fsdb"))

