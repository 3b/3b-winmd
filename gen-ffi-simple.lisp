(in-package #:3b-winmd)
;; try to generate some minimally usable CFFI definitions suitable for
;; cutting and pasting individual bits into other projects
;;

(defvar *cffi-package* "") ;; or "cffi:"
(defvar *include-library* t)

(defvar *cffi-simple-seen* (make-hash-table))


(defun lookup-type (namespace type)
  (gethash (list namespace type) *type-def-by-name*))

(defun lookup-type-ref (ref)
  (let ((n (reverse
            (loop for type1 = ref
                    then (type-ref-resolution-scope type1)
                  for ns = (type-ref-type-namespace type1)
                  collect (type-ref-type-name type1)
                  when ns
                    collect ns
                  until ns))))
    (or (gethash n *type-def-by-name*)
        (name ref))))


(defun lookup-function (namespace method &key (type "Apis"))
  (let ((type (gethash (list namespace type) *type-def-by-name*)))
    (find method (type-def-method-list type) :key #'method-def-name :test 'string=)))


(defmethod gen-cffi-simple :around ((x t) &key)
  ;; filter out stuff we already dumped, so we can dump things
  ;; recursively from a definition, and do a few at once
  (cond
    ((gethash x *cffi-simple-seen*)
     ;; do nothing
     )
    (t
     ;; avoid infinite loops
     (setf (gethash x *cffi-simple-seen*) :generating)
     (prog1 (call-next-method)
       ;; not sure we need to distinguish successful dump, but might as well
       (setf (gethash x *cffi-simple-seen*) t)))))


(defmethod gen-cffi-simple :around ((x type-def) &key)
  ;; filter out some types used by the metadata format
  (unless (equal (type-def-type-namespace x)
                 "Windows.Win32.Foundation.Metadata")
    (call-next-method)))

(defmethod gen-cffi-simple ((m type-ref) &key)
  (let ((td (lookup-type (type-ref-type-namespace m)
                         (type-ref-type-name m))))
    (when td (gen-cffi-simple td))))

(defmethod gen-cffi-simple ((m method-def) &key)
  (let* ((imp (gethash m *impl-map-index*))
         #++(att (gethash m *attribute-plist*))
         (params (method-def-param-list m))
         (sig (method-def-signature m))
         (sigparam (blob-signature-param sig))
         #++
         (rt (get-sig-param-type-info (blob-signature-return-type sig)
                                      :deref nil))
         (st (map 'vector (a:rcurry 'get-sig-param-type-info
                                    :deref nil)
                  sigparam))
         (vararg nil)
         (conv (ecase (blob-signature-flags-conv sig)
                 (:default nil)
                 (:vararg (setf vararg t) nil))))
    (unless (and (= (method-def-impl-flags m) 0)
                 (= (method-def-flags m) #x2096))
      (break "flags ~x = ~s~% ~x = ~s"
             (method-def-impl-flags m)
             (method-impl-attributes-as-keys
              (method-def-impl-flags m))
             (method-def-flags m)
             (method-attributes-as-keys
              (method-def-flags m))))
    (assert imp)
    ;; recursively dump argument and return types
    (let ((rt (blob-signature-return-type sig)))
      (etypecase rt
        ((or (cons (eql :type))
             (cons integer (cons integer (cons symbol))))
         ;; base types
         )
        ((cons integer (cons integer))
         (gen-cffi-simple (third rt)))
        ((cons (eql :class))
         (gen-cffi-simple (second rt)))
        ((cons (eql :value-type))
         (gen-cffi-simple (second rt)))
        ((cons (eql :ptr))
         (when (getf rt :value-type)
           (gen-cffi-simple (getf rt :value-type))))
        ((or type-ref type-def)
         (gen-cffi-simple rt))))
    (loop for p across sigparam
          for vt = (getf p :value-type)
          do (etypecase vt
               (null)
               ((or type-ref type-def)
                (gen-cffi-simple vt))))
    (format t "~&~%(~adefcfun (~s ~a ~@[:library ~a~]~@[ :convention ~a~])~%"
            *cffi-package*
            (name m)
            (translate-camelcase (name m))
            (when *include-library*
              (translate-dll-name-for-ffi
               (module-ref-name (impl-map-import-scope imp))))
            conv)
    ;; sometimes params has an entry for return type and
    ;; sometimes not (and there might be attributes on it if
    ;; it exists, so need to account for that if we start
    ;; handling things like :const or :not-null-terminated
    ;; automatically (or at least dump them into comments)
    (assert
     (or (= (length params) (length st))
         (= (length params) (1+ (length st)))))
    (format t "~&   ~a"
            (translate-param-type/simple (blob-signature-return-type sig)))
    (loop for p across params
          for seq = (param-sequence p)
          for name = (param-name p)
          for type = (unless (zerop seq) (aref sigparam (1- seq)))
          for att = (gethash p *attribute-plist*)
          for i = (when type (translate-param-type/simple type))
          for n = (when name
                    (translate-arg-name-for-ffi name))
          when att
            do (format t "~&  ;;~{ ~s ~s~}~%" att)
          unless (zerop seq)
            do (format t "~&  (~a ~a)" n i
                       #++ (if (symbolp i) (format nil "~(~s~)"i) i)))
    (when vararg (format t "~&  &rest"))
    (format t ")~%")))

(defun translate-param-type/simple (pt)
  (flet ((ptr? (x)
           (loop repeat (count :ptr pt)
                 do #++(setf x (list :pointer x))
                    (setf x (format nil "(:pointer ~a)" x)))
           x))
    (etypecase pt
      ((cons (eql :array))
       (ptr? (translate-type-name-for-ffi/simple pt)))
      ((cons (eql :class))
       ;; not sure if these are right, mostly function pointer types?
       (ptr? (translate-type-name-for-ffi/simple (second pt))))
      (cons
       (let* ((vt (getf pt :value-type))
              (tt (getf pt :type))
              (ct (getf pt :class)))
         (assert (not (and vt tt ct)))
         (ptr? (translate-type-name-for-ffi/simple (or vt tt ct))))))))

(defun expand-struct/union-slots/simple (x)
  (destructuring-bind (size align base) (gethash x *type-def-info*)
    (assert (and size align base))
    (let ((nested-types (make-hash-table :test 'equalp)))
      (flet ((align (x a)
               (* a (ceiling x a)))
             (array-size (sig)
               (when (getf sig :array)
                 (destructuring-bind (&key array rank sizes low) sig
                   (declare (ignore array))
                   ;; todo: arrays with low bounds? (probably not needed
                   ;; for winmd files?)
                   (assert (every 'zerop low))
                   ;; todo: arrays like foo[12][34][][]
                   (assert (= (length sizes) rank))
                   (list :count (reduce '* sizes)))))
             (nested-anonymous (pt)
               (let* ((vt (getf pt :value-type)))
                 ;; we have a type-ref
                 (when (and vt (typep vt 'type-ref)
                            ;; actual type, not a pointer to it
                            (not (getf pt :ptr))
                            ;; to a type nested in this one
                            (or (eql (type-ref-resolution-scope vt) x)
                                ;; or a ref to this one
                                (ns-equal (type-ref-resolution-scope vt)
                                          (type-def-type-namespace x)
                                          (type-def-type-name x))))
                   (gethash (type-ref-type-name vt) nested-types)))))
        (loop for nc in (gethash x *enclosing-class-index*)
              for i = (nested-class-nested-class nc)
              for slots =(expand-struct/union-slots/simple i)
              do (setf (gethash (type-def-type-name i) nested-types)
                       slots))

        (loop with offset = 0
              for f across (type-def-field-list x)
              for sig = (aref (blob-signature-param (field-signature f)) 0)
              for (fs fa ft) = (get-field-type-info f)
              for na = (nested-anonymous sig)
              for fl = (gethash f *layout-index*)
              when fl
                do (setf offset (field-layout-offset fl))
              else do (setf offset (align offset fa))
              when na
                collect (format nil ";; nested anonymous: ~s" (name f))
                and append (loop for ns in na
                                 for (sn st . sk) = (when (consp ns) ns)
                                 for (an nn) = (when (consp ns)
                                                 (multiple-value-list
                                                  (a:starts-with-subseq
                                                   "Anonymous" (field-name f)
                                                   :return-suffix t)))
                                 when (consp ns)
                                   do (incf (getf sk :offset) offset)
                                   and collect (list* (if (and an
                                                               (every 'digit-char-p
                                                                      nn))
                                                          sn
                                                          (format nil "~a.~a"
                                                                  (field-name f)
                                                                  sn))
                                                      st sk)
                                 else collect ns)
              else
                collect `(,(name f)
                          ,(translate-param-type/simple sig)
                          ,@(array-size sig)
                          :offset ,offset)
              do (incf offset fs))))))

(defun typedef-p (x)
  (let ((at (gethash x *attribute-plist*))
        (fl (type-def-field-list x)))
    (when (getf at :native-typedef)
      (assert (= 1 (length fl)))
      (let* ((f (aref fl 0))
             (s (field-signature f))
             (p (aref (blob-signature-param s) 0)))
        (assert (string= (field-name f) "Value"))
        p))))

(defun translate-type-name-for-ffi/simple (x)
  (cond
    ((member x '(:u1 :i1 :u2 :i2 :u4 :i4 :u8 :i8 :r4 :r8 :ptr :string
                 :char :boolean :u :i))
     (format nil "~(~s~)"(third (gethash x *base-types*))))
    ((typep x '(cons (eql :array)))
     (let ((tt (getf (second x) :type))
           (vt (getf (second x) :value-type))
           (ct (getf (second x) :class)))
       (assert (or tt vt ct))
       (if ct
           ":pointer"
           (translate-type-name-for-ffi/simple (or vt tt ct)))))
    ((typep x 'type-ref)
     (translate-type-name-for-ffi/simple (lookup-type-ref x)))
    ((not x)
     (break "??"))
    (t
     (let ((name (if (symbolp x)
                     (format nil "~(~s~)" x)
                     (translate-camelcase (if (stringp x)
                                              x
                                              (namespaced-name/s x))))))
       (if (and (typep x 'type-def)
                (member (type-def-flags x) '(#x00100109 #x00100111 #x4109))
                (not (typedef-p x)))
           (format nil "(:struct ~a)" name)
           (format nil "~(~a~)" name))))))

(defun gen-cffi-simple/struct (x)
  (destructuring-bind (size align base) (gethash x *type-def-info*)
    (assert (and size align base))
    (let ((nested-types (make-hash-table :test 'equalp)))
      (labels (#++
               (align (x a)
                 (* a (ceiling x a)))
               #++
               (array-size (sig)
                 (when (getf sig :array)
                   (destructuring-bind (&key array rank sizes low) sig
                     (declare (ignore array))
                     ;; todo: arrays with low bounds? (probably not needed
                     ;; for winmd files?)
                     (assert (every 'zerop low))
                     ;; todo: arrays like foo[12][34][][]
                     (assert (= (length sizes) rank))
                     (list :count (reduce '* sizes)))))
               (nested-anonymous-p (pt vt)
                 (and vt (typep vt 'type-ref)
                      ;; actual type, not a pointer to it
                      (not (getf pt :ptr))
                      ;; to a type nested in this one
                      (or (eql (type-ref-resolution-scope vt) x)
                          ;; or a ref to this one
                          (ns-equal (type-ref-resolution-scope vt)
                                    (type-def-type-namespace x)
                                    (type-def-type-name x)))))
               (nested-anonymous (pt)
                 (let* ((vt (getf pt :value-type)))
                   ;; we have a type-ref
                   (when (nested-anonymous-p pt vt)
                     (gethash (type-ref-type-name vt) nested-types)))))

        ;; find nested types
        (loop for nc in (gethash x *enclosing-class-index*)
              for i = (nested-class-nested-class nc)
              do (multiple-value-bind (slots)
                     (expand-struct/union-slots/simple i)
                   (setf (gethash (type-def-type-name i) nested-types)
                         slots)))

        ;; recursively dump slot types
        (when (type-def-extends x)
          (gen-cffi-simple (type-def-extends x)))
        (loop for f across (type-def-field-list x)
              for s = (field-signature f)
              for p = (blob-signature-param s)
              for pt = (aref p 0)
              for vt = (getf pt :value-type)
              for ct = (getf pt :class)
              for na = (nested-anonymous pt)
              do (Assert (= 1 (length p)))
              #++(when (string= (field-name f)
                                "SymLoadCallback")
                   (break "~s" f))
                 (when vt
                   (gen-cffi-simple vt))
                 (when ct
                   (gen-cffi-simple ct))
                 (when na
                   (loop for ns in na
                         for (n st . r) = (when (consp ns) ns)
                         do (when (typep ns '(or type-def type-ref))
                              (gen-cffi-simple st)))))
        ;; typedefs
        (let ((td (typedef-p x)))
          (when td
            (format t "~&~%(~adefctype ~a ~a)~%"
                    *cffi-package*
                    (translate-type-name-for-ffi/simple (type-def-type-name x))
                    (translate-param-type/simple td))
            (return-from gen-cffi-simple/struct nil)))

        #++(format t "~&~%~s~%"
                   `(cffi:defcstruct ,(format nil "~a::~a"
                                              (translate-namespace-for-ffi x)
                                              (translate-struct-name-for-ffi x))
                      ,@ (expand-struct/union-slots x)))
        (format t "~&~%(~adefcstruct ~a" *cffi-package*
                (translate-struct-name-for-ffi x))
        (loop for ns in (expand-struct/union-slots/simple x)
              for (n st . r) = (when (consp ns) ns)
              do (if (consp ns)
                     (progn
                       (assert st)
                       (assert (not (string= st "nil")))
                       (format t "~&  (~a ~a~(~{ ~s~}~))"
                               (translate-camelcase n)
                               st #++(translate-type-name-for-ffi/simple st)
                               r))
                     (format t "~&  ~a" ns)))

        #++(loop with offset = 0
                 for f across (type-def-field-list x)
                 for sig = (aref (blob-signature-param (field-signature f)) 0)
                 for (fs fa ft) = (get-field-type-info f)
                 for na = (nested-anonymous sig)
                 for fl = (gethash f *layout-index*)
                 when fl
                   do (setf offset (field-layout-offset fl))
                 else do (setf offset (align offset fa))
                 when na
                   do (format t "~&  ;; nested anonymous: ~s" (field-name f))
                      (loop for (sn st . sk) in na
                            for (an nn) = (multiple-value-list
                                           (a:starts-with-subseq
                                            "Anonymous" (field-name f)
                                            :return-suffix t))
                            do (incf (getf sk :offset) offset)
                            do #++(list* (if (and an
                                                  (every 'digit-char-p
                                                         nn))
                                             sn
                                             (format nil "~a.~a"
                                                     (field-name f)
                                                     sn))
                                         st sk)
                               (format t "~&  (~a ~a ~a)"
                                       (if (and an
                                                (every 'digit-char-p
                                                       nn))
                                           sn
                                           (format nil "~a.~a"
                                                   (field-name f)
                                                   sn))
                                       st sk))
                 else
                   do (format t "~&  (~a" (translate-camelcase (name f)))
                      (if (typep ft '(cons (eql :array)))
                          (format t " 1~a"
                                  (translate-type-name-for-ffi (second ft)))
                          (format t " 2~a"
                                  (let ((ttn (translate-type-name-for-ffi ft)))
                                    (if (stringp ttn)
                                        ttn
                                        (format nil "~(~s~)" ttn)))))
                      (format t "~{ ~a~}" (array-size sig))
                      (format t " :offset ~a" offset)
                      (format t ")")
                 do (incf offset fs)))))
 
  (format t ")~%"))
(defmethod gen-cffi-simple ((x type-def) &key nested in-flag)
  (declare (ignorable nested in-flag))
  (unless (or ;; ignore some types used by the metadata format
           (string= (type-def-type-namespace x)
                    "Windows.Win32.Foundation.Metadata")
           (let ((sa (getf (gethash x *attribute-plist*) :supported-architecture)))
             (when (and sa (not (member *architecture* sa))
                        (string= (name x) "MEMORY_BASIC_INFORMATION"))
               (format t "drop ~s ~s~%"
                       sa (namespaced-name/s x)))
             (and sa (not (member *architecture* sa)))))
    (case (type-def-flags x)
      (0 ;; module?
       (assert (string= (type-def-type-name x) "<Module>")))
      (#x00120181 ;; global namespace def
       ;; (:BEFORE-FIELD-INIT :AUTO-CLASS :SEALED :ABSTRACT :CLASS
       ;; :AUTO-LAYOUT :PUBLIC)
       (assert (string= (type-def-type-name x) "Apis"))
       (format t "~&;;todo: global namespace:~%;; ~a::~a~%;; ~s fields~%;; ~s methods~%;; ~s nested class~%;;extends ~a~%"
               (type-def-type-namespace x) (type-def-type-name x)
               (length (type-def-field-list x))
               (length (type-def-method-list x))
               (length (gethash x *enclosing-class-index*))
               (when (type-def-extends x)
                 (let ((ns (namespaced-name (type-def-extends x))))
                   (if ns
                       (format nil "~a::~a" (getf ns :namespace) (getf ns :name))
                       (name (type-def-extends x))))))
       (when (gethash x *enclosing-class-index*)
         (break "global namespace:~% ~a::~a~% ~s fields~% ~s methods~% ~s nested class~%extends ~a"
                (type-def-type-namespace x) (type-def-type-name x)
                (length (type-def-field-list x))
                (length (type-def-method-list x))
                (length (gethash x *enclosing-class-index*))
                (when (type-def-extends x)
                  (let ((ns (namespaced-name (type-def-extends x))))
                    (if ns
                        (format nil "~a::~a" (getf ns :namespace) (getf ns :name))
                        (name (type-def-extends x)))))))
       ;; just dump fields as constants for now.
       (loop for f across (type-def-field-list x)
             for att = (gethash f *attribute-plist*)
             for fl = (gethash f *layout-index*)
             for fc = (gethash f *constant-index*)
             for fca = (getf att :constant)
             for has-constant = (or fc fca)
             for guid = (getf att :guid)
             for docs = (getf att :documentation)
             for param = (aref (blob-signature-param
                                (field-signature f))
                               0)
             for type = (or (getf param :ptr)
                            (getf param :type)
                            (getf param :value-type))
             do (when docs
                  (format t "~&~%;; ~a~%" docs))
                (when (and fc fca)
                  (break "multiple constants for field ~s?~%constant= ~s~%att=~s"
                         (namespaced-name/s f)
                         (constant-value fc) fca))
                (if fc
                    (setf fc (constant-value fc))
                    (setf fc fca))
                (remf att :guid)
                (remf att :constant)
                (remf att :documentation)
                (cond
                  ((and has-constant (not fc) (not guid))
                   ;; interpretation depends on type
                   (cond
                     ((eql type :string)
                      (format t "(a:define-constant ~a ~s :test :string=)~@[;; ~{ ~s ~s~}~]~%"
                              (namespaced-name/s f)
                              ""
                              att))
                     (t (break "nil constant ~s~%~s"
                               (namespaced-name/s f)
                               (aref (blob-signature-param
                                      (field-signature f))
                                     0)))))
                  ((and fc (numberp fc) (not guid))
                   (let* ((fcp fc)
                         (vt (getf param :value-type))
                         (n (when vt (name vt))))
                     ;; print NTSTATUS, HRESULT, etc as hex, with
                     ;; negative as (- #xabcd1234) since they are
                     ;; usually described that way in specs
                     (when (or (equal n "HRESULT")
                               (equal n "NTSTATUS")
                               (equal n "SCODE"))
                       (assert (<= (integer-length fcp) 32))
                       (setf fcp (if (minusp fcp)
                                     (format nil "(- #x~8,'0x)"
                                             (ldb (byte 32 0) fcp))
                                     (format nil "#x~8,'0x" fcp))))
                     (format t "(defconstant ~a ~a)~@[;; ~{ ~s ~s~}~]~%"
                             (namespaced-name/s f)
                             fcp
                             att)))
                  ((and fc (stringp fc) (not guid))
                   (format t "(alexandria:define-constant ~a ~s :test 'string=)~@[;; ~{ ~s ~s~}~]~%"
                           (namespaced-name/s f)
                           fc
                           att))
                  ((and (not fc) guid)
                   (format t "(alexandria:define-constant ~a ~s :test 'string=)~@[;; ~{ ~s ~s~}~]~%"
                           (namespaced-name/s f)
                           (apply #'format nil "~8,'0x-~4,'0x-~4,'0x-~2,'0x~2,'0x-~@{~2,'0x~}"
                                  guid)
                           att))
                  ((and (typep type 'type-ref)
                        (ns-equal type "Windows.Win32.UI.Shell.PropertiesSystem"
                                  "PROPERTYKEY"))
                   (format t ";; ?? no value for ~s~%"
                           (namespaced-name/s f)))
                  (t (format t "?~s ~s~%" (not fc) guid)
                     (break "?~s~% ~s~% ~s~% ~s~%" fl fc att f))))
       ;; dump defcfun for methods
       (map 'nil 'gen-cffi-simple (type-def-method-list x)))
      ((#x00000101 #x00120101 #x00004101)
       ;; enum, delegate, some classes used by metadata, WinRT enum or
       ;; delegate
       (cond
         ((ns-equal (type-def-extends x) "System" "Enum")
          ;; field: flag = #x601,name="value__" = enum type
          ;; field: flag = #x8056 = enum name constant:
          ;; parent=field = enum value CustomAttribute:
          ;; FlagsAttribute => bit flag
          (assert (ns-equal (type-def-extends x) "System" "Enum"))
          (assert (zerop (length (type-def-method-list x))))
          (assert (zerop (length (gethash x *enclosing-class-index*))))
          (when (zerop (length (type-def-field-list x)))
            (break "enum ~s has 0 fields?" (namespaced-name x)))

          (let* ((base-type (translate-type-name-for-ffi
                             (third (get-field-type-info
                                     (aref (type-def-field-list x) 0)))))
                 (flag-p (getf (gethash x *attribute-plist*) :flag-p))
                 (name (translate-enum-type-name-for-ffi x flag-p))
                 #++(slots (loop for f across (type-def-field-list x)
                                 for cc = (gethash f *constant-index*)
                                 for c = (when cc (constant-value cc))
                                 unless (string= (field-name f) "value__")
                                   collect `(,(translate-enum-name-for-ffi
                                               f x flag-p)
                                             ,c)))
                 r)
            #++
            (if flag-p
                (setf r
                      `(cffi:defbitfield ,name ,@slots))
                (setf r `(cffi:defcenum ,name ,@slots)))
            (let ((*print-level* nil))
              #++(format t "~&~s~%" r)
              (format t "~&~%(~a~a (~a ~(~s~))" *cffi-package*
                      (if flag-p "defbitfield" "defcenum")
                      name base-type)
              (loop for f across (type-def-field-list x)
                    for cc = (gethash f *constant-index*)
                    for c = (when cc (constant-value cc))
                    unless (string= (field-name f) "value__")
                      do (format t "~&  (:~a ~a)"
                                 (translate-enum-name-for-ffi f x flag-p)
                                 (if flag-p
                                     (format nil "#x~8,'0x" c)
                                     c)))
              (format t ")~%"))
            r))

         ((ns-equal (type-def-extends x) "System" "MulticastDelegate")
          (assert (zerop (length (type-def-field-list x))))
          (assert (= 2 (length (type-def-method-list x))))
          (assert (zerop (length (gethash x *enclosing-class-index*))))
          (assert (string= (method-def-name (aref (type-def-method-list x) 0))
                           ".ctor"))
          (assert (string= (method-def-name (aref (type-def-method-list x) 1))
                           "Invoke"))
          (let* ((invoke (aref (type-def-method-list x) 1))
                 (param (method-def-param-list invoke))
                 (sig (method-def-signature invoke))
                 (rt (get-sig-param-type-info (blob-signature-return-type sig)
                                              :deref nil)))
            (format t "~&~%")
            (unless (and (member (method-def-flags invoke)
                                 '(#x1c6))
                         (member (method-def-impl-flags invoke)
                                 '(#x3))
                         (member (blob-signature-flags
                                  (method-def-signature invoke))
                                 '(#x20)))
              (format t ";; ~x ~s~%"
                      (method-def-flags invoke)
                      (method-attributes-as-keys
                       (method-def-flags invoke)))
              (format t ";; ~x ~s~%"
                      (method-def-impl-flags invoke)
                      (method-impl-attributes-as-keys
                       (method-def-impl-flags invoke)))
              (format t ";; ~x ~s~%"
                      (blob-signature-flags
                       (method-def-signature invoke))
                      (signature-flags-as-keys
                       (blob-signature-flags
                        (method-def-signature invoke))))
              (break "delegate ~s~%" x))
            (unless (a:emptyp param)
              (loop for i from (param-sequence (aref param 0))
                    for p across param
                    for seq = (param-sequence p)
                    for name = (param-name p)
                    for s = (unless (zerop seq)
                              (aref (blob-signature-param sig) (1- seq)))
                    for type = (when s
                                 (translate-param-type/simple s))
                    for att = (gethash p *attribute-plist*)
                    when (or att (not (zerop seq)))
                      do (format t ";; (~s ~s)~@[~{ ~s ~s~}~]~%"
                                 name
                                 (when type
                                   (translate-type-name-for-ffi
                                    (if (consp type) (third type) type)))
                                 att)
                    do (assert (= i seq))))
            (format t ";;  -> ~s~%"
                    (translate-type-name-for-ffi
                     (if (consp rt) (third rt) rt)))
            (format t "(~adefctype ~a (:pointer))~%"
                    *cffi-package*
                    (translate-type-name-for-ffi (type-def-type-name x))))
          (when (position #\` (type-def-type-name x))
            (break "todo parameterized delegate ~s"
                   (namespaced-name x))
            ;; = parameterized delegate
            ;;  adds row(s) in generic-param table specifying generic types
            )
          (format t ";; todo: generate ffi for delegates/function pointers ~s~%"
                  (namespaced-name/s x)))
         (t (error "unexpected base type ~s?"
                   (namespaced-name (type-def-extends x))))))
      ((#x0010010A #x00100112) ;; nested struct/union
       ;; we ignore nested struct/union here, and expand them inline
       ;; into parent for generated ffi, since nothing else could be
       ;; using the type even if it were accessible as a whole (and
       ;; people can use cffi:foreign-slot-pointer to the first element
       ;; if they did need to access it as a whole.) may or may not
       ;; generate a slot for the whole nested struct, don't know yet.
       (assert (gethash x *nested-class-index*)))
      ((#x00100109 #x00100111 #x4109) ;; struct, union, winrt struct
       (assert (ns-equal (type-def-extends x) "System" "ValueType"))
       (assert (zerop (length (type-def-method-list x))))
       (gen-cffi-simple/struct x))
      ((#x000000A1 #x40a1 #x40a0) ;; interface
       (assert (zerop (length (type-def-field-list x))))
       (let ((r `(org.shirakumo.com-on:define-comstruct
                     ,(translate-interface-name-for-ffi x)
                   ,@ (loop
                        for m across (type-def-method-list x)
                        for sig = (blob-signature-param
                                   (method-def-signature m))
                        for params = (method-def-param-list m)
                        for rt = (get-sig-param-type-info
                                  (blob-signature-return-type
                                   (method-def-signature m))
                                  :deref nil)
                        for st = (map 'vector
                                      (a:rcurry 'get-sig-param-type-info
                                                :deref nil)
                                      sig)
                        do ;; sometimes params has an entry for return
                           ;; type and sometimes not (and there might
                           ;; be attributes on it if it exists, so
                           ;; need to account for that if we start
                           ;; handling things like :const or
                           ;; :not-null-terminated automatically (or
                           ;; at least dump them into comments)
                           (assert
                            (or (= (length params) (length st))
                                (= (length params) (1+ (length st)))))
                        collect `(,(translate-function-name-for-ffi m)
                                  ,(translate-type-name-for-ffi
                                    (if (consp rt) (third rt) rt))
                                  ,@(loop
                                      for p across params
                                      for seq = (param-sequence p)
                                      for name = (param-name p)
                                      for type = (unless (zerop seq)
                                                   (aref st (1- seq)))
                                      for att = (gethash p *attribute-plist*)
                                      for i = (when type
                                                (translate-type-name-for-ffi
                                                 (if (consp type)
                                                     (third type)
                                                     type)))
                                      for n = (when name
                                                (translate-arg-name-for-ffi
                                                 name))
                                      when att
                                        collect `(:comment ,seq ,@att)
                                      unless (zerop seq)
                                        collect (list n i)))))))
         (format t "~&~%~s~%" r)
         r))
      (t (break "unknown flag combination #x~8,'0x  in typedef~%~s~%~a::~a~%~s fields~%~s methods~%~s nested classes~% extends ~a"
                (type-def-flags x)
                (type-attributes-as-keys (type-def-flags x))
                (type-def-type-namespace x) (type-def-type-name x)
                (length (type-def-field-list x))
                (length (type-def-method-list x))
                (length (gethash x *enclosing-class-index*))
                (when (type-def-extends x)
                  (let ((ns (namespaced-name (type-def-extends x))))
                    (if ns
                        (format nil "~a::~a" (getf ns :namespace) (getf ns :name))
                        (name (type-def-extends x))))))))))



;;; dump entire ffi
#++
(let ((*cffi-simple-seen* (make-hash-table))
      (*cffi-package* "cffi:")
      (*translate-names-with-namespaces* nil)
      (*include-library* nil))
  (with-winmd (w #p"~/quicklisp/local-projects/3b-winmd/md/Windows.Win32.winmd")
    (with-open-file (*standard-output*
                     #p"~/quicklisp/local-projects/3b-win32/ffi.generated.simple.lisp"
                     :direction :output :if-exists :supersede)
      (with-standard-io-syntax
        (let ((*print-pretty* t)
              (*print-readably* nil))
          (map nil 'gen-cffi-simple (get-table w 'type-def))))
      nil)))

;;; dump specific definitions
#++
(let ((*cffi-simple-seen* (make-hash-table))
      (*cffi-package* "cffi:")
      (*translate-names-with-namespaces* nil))
  (let ((types '(("Windows.Win32.Media.Audio" "IMMDeviceEnumerator")))
        (functions '(("Windows.Win32.Foundation" "GetLastError")
                     ("Windows.Win32.Devices.Display" "QueryDisplayConfig"))))
    (with-winmd (w #p"~/quicklisp/local-projects/3b-winmd/md/Windows.Win32.winmd")
      (loop for (ns n) in types do (gen-cffi-simple (lookup-type ns n)))
      (loop for (ns n) in functions do (gen-cffi-simple (lookup-function ns n))))))
#++(ql:quickload '3b-winmd)
#++
(let ((*cffi-simple-seen* (make-hash-table))
      (*cffi-package* "cffi:")
      (*translate-names-with-namespaces* nil))
  (let ((types '())
        (functions '(("Windows.Win32.Foundation" "GetLastError")
                     ("Windows.Win32.Devices.Display" "QueryDisplayConfig"))))
    (with-winmd (w #p"~/quicklisp/local-projects/3b-winmd/md/Windows.Win32.winmd")
      (loop for (ns n) in types do (gen-cffi-simple (lookup-type ns n)))
      (loop for (ns n) in functions do (gen-cffi-simple (lookup-function ns n))))))



