package com.example.keyboxchecker

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import java.text.SimpleDateFormat
import java.util.*

class CertificateAdapter : RecyclerView.Adapter<CertificateAdapter.VH>() {

    private val items = mutableListOf<KeyboxChecker.CertInfo>()
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)

    fun setItems(list: List<KeyboxChecker.CertInfo>) {
        items.clear()
        items.addAll(list)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_certificate, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val info = items[position]
        holder.tvSubject.text = info.subject
        holder.tvIssuer.text = "Issuer: ${info.issuer}"
        holder.tvValidity.text = "Validity: ${dateFmt.format(info.notBefore)} → ${dateFmt.format(info.notAfter)}"
        holder.tvSerial.text = "Serial: ${info.serialHex}"
        holder.tvFingerprint.text = "SHA-256: ${info.sha256Fingerprint}"
        holder.tvCompareHex.text = "Compared hex: ${info.comparedHex}"
        holder.tvStatus.text = if (info.revoked) "❌ Revoked" else "✅ Not revoked"
        holder.tvStatus.setTextColor(if (info.revoked) Color.RED else Color.parseColor("#006400"))
    }

    override fun getItemCount(): Int = items.size

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvSubject: TextView = view.findViewById(R.id.tvSubject)
        val tvIssuer: TextView = view.findViewById(R.id.tvIssuer)
        val tvValidity: TextView = view.findViewById(R.id.tvValidity)
        val tvSerial: TextView = view.findViewById(R.id.tvSerial)
        val tvFingerprint: TextView = view.findViewById(R.id.tvFingerprint)
        val tvCompareHex: TextView = view.findViewById(R.id.tvCompareHex)
        val tvStatus: TextView = view.findViewById(R.id.tvStatus)
    }
}
