using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JCryptology.Utils
{
    public class ByteUtil
    {
        #region Variables
        protected List<byte> Bytes;
        private int Pointer;
        #endregion

        #region Getters
        public int Length
        {
            get
            {
                return Bytes.Count;
            }
        }

        public int BytesRemain
        {
            get
            {
                return Length - Pointer;
            }
        }
        #endregion

        #region Constructors
        public ByteUtil(byte[] _Bytes)
        {
            this.Bytes = _Bytes.ToList();
            this.Pointer = 0;
        }

        public ByteUtil()
        {
            this.Bytes = new List<byte>();
            this.Pointer = 4;
        }
        #endregion

        #region Readers
        public byte[] ReadBytes(int _Length, bool _Reverse = false)
        {
            if (_Length > BytesRemain)
            {
                _Length = BytesRemain;
            }

            List<byte> Result = new List<byte>(_Length);

            for (int i = 0; i < _Length; i++)
            {
                Result.Add(Bytes[Pointer++]);
            }

            if (_Reverse)
            {
                Result.Reverse();
            }

            return Result.ToArray();
        }

        public byte[] ReadBytes(int _StartOff, int _Length, bool _Reverse = false)
        {
            if (_Length > BytesRemain)
            {
                _Length = BytesRemain;
            }

            List<byte> Result = new List<byte>(_Length);

            for (int i = 0, j = _StartOff; i < _Length; i++, j++)
            {
                Result.Add(Bytes[j]);
            }

            if (_Reverse)
            {
                Result.Reverse();
            }

            return Result.ToArray();
        }
        #endregion

        #region Setters
        public void WriteBytes(byte[] _Bytes, bool _Reverse = false)
        {
            List<byte> TBytes = _Bytes.ToList();

            if (_Reverse)
            {
                TBytes.Reverse();
            }

            foreach (byte Byte in TBytes)
            {
                Bytes.Add(Byte);
            }
        }
        #endregion
    }
}
