;;
;; Utility functions
;; 

(in-package #:cl-rsasign)

(defvar *use-urandom* t)
(defvar *use-random* t)

(defun slurp-stream (stream) 
  (let ((seq (make-string (file-length stream)))) 
    (read-sequence seq stream) seq))

(defun urandom-stream ()
  (and *use-urandom*
       (or (ignore-errors
	     #-windows (open "/dev/urandom" :external-format :ISO-8859-1)
	     #+windows *windows-random-stream*)
           (setq *use-urandom* nil))))

(defun random-stream ()
  (and *use-random*
       (or (ignore-errors
	     #-windows (open "/dev/random" :external-format :ISO-8859-1)
	     #+windows *windows-random-stream*)
           (setq *use-random* nil))))

(defun random-bytes (num &optional (stream (random-stream)))
  "Return NUM random bytes from /dev/random as a string"
  (when (< num 0)
    (error "Number of bytes must be non-negative"))
  (unwind-protect
       (with-output-to-string (s)
         (if stream
             (dotimes (i num) (write-char (read-char stream) s))
             (dotimes (i num) (write-char (code-char (random 256)) s))))
    (when stream (close stream))))

(defun urandom-bytes (num)
  "Return $num random bytes from /dev/urandom as a string"
  (random-bytes num (urandom-stream)))

(defun destroy-passphrase (buf &optional
                          (len (length buf))
                          (store-fun 'aset))
  "Overwrite a passphrase string with randomness"
  (let* ((s-len (max 8 len))
         (s (urandom-bytes s-len)))
    (dotimes (i len)
      (dotimes (j 8)
        (funcall store-fun (aref s (mod (+ i j) s-len)) buf i)))))

(defun copy-memory-to-lisp (pointer len byte-array-p)
  (let ((res (if byte-array-p
                 (make-array len :element-type '(unsigned-byte 8))
                 (make-string len))))
    (dotimes (i len)
      (let ((byte (mem-ref pointer :unsigned-char i)))
        (setf (aref res i)
              (if byte-array-p byte (code-char byte)))))
    res))

(defun copy-lisp-to-memory (array pointer &optional (start 0) (end (length array)))
  (loop
     with stringp = (typep array 'string)
     for i from start below end
     for p from 0
     for elt = (aref array i)
     for byte = (if stringp (char-code elt) elt)
     do
       (setf (mem-ref pointer :unsigned-char p) byte)))

(defun hex (integer)
  "Return a string encoding integer as hex"
  (format nil "~x" integer))

(defun as-hex (byte)
  (when (or (< byte 0) (> byte 15))
    (error "Not between 0 and 15: ~s" byte))
  (code-char
   (if (< byte 10)
       (+ byte #.(char-code #\0))
       (+ (- byte 10) #.(char-code #\a)))))

(defun as-bin (hex-char)
  (let ((code (char-code hex-char)))
    (cond ((< code #.(char-code #\0))
           (error "Not a hex character: ~s" hex-char))
          ((<= code #.(char-code #\9)) (- code #.(char-code #\0)))
          ((and (>= code #.(char-code #\a))
                (<= code #.(char-code #\f)))
           (+ 10 (- code #.(char-code #\a))))
          ((and (>= code #.(char-code #\A))
                (<= code #.(char-code #\F)))
           (+ 10 (- code #.(char-code #\A))))
          (t (error "Not a hex character: ~s" hex-char)))))

(defun bin2hex (thing)
  "Convert an integer or byte array or string to a hex string"
  (if (integerp thing)
      (format nil "~x" thing)
      (let ((stringp (stringp thing)))
        (with-output-to-string (s)
          (dotimes (i (length thing))
            (let* ((elt (aref thing i))
                   (byte (if stringp (char-code elt) elt))
                   (hi (ash byte -4))
                   (lo (logand byte #xf)))
              (write-char (as-hex hi) s)
              (write-char (as-hex lo) s)))))))

(defun hex2bin (hex &optional res-type)
  "Convert a hex string to binary.
   Result is a byte-string if res-type is :bytes,
   a string if res-type is :string,
   or an integer otherwise (the default)."
  (let* ((len (length hex))
         (bytes (ash (1+ len) -1))
         (res (cond ((eq res-type :string) (make-string bytes))
                    ((eq res-type :bytes)
                     (make-array bytes :element-type '(unsigned-byte 8)))
                    (t nil)))
         (accum 0)
         (cnt (if (evenp len) 2 1))
         (idx -1))
    (dotimes (i len)
      (setq accum (+ (ash accum 4) (as-bin (aref hex i))))
      (when (and res (eql 0 (decf cnt)))
        (setf (aref res (incf idx))
              (if (eq res-type :bytes)
                  accum
                  (code-char accum)))
        (setq accum 0
              cnt 2)))
    (or res accum)))

(defun base64-encode (string &optional (columns 64))
  (string-to-base64-string string :columns columns))
